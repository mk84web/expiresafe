#!/usr/bin/env python3
"""
ExpireSafe Backup Utility
─────────────────────────
Backs up the TWO things that matter:
  1. The database  (instance/expiresafe.db)
  2. The uploads   (uploads/)

Backups are stored in dated folders:
  backups/
    ├── 2026-02-04/
    │   ├── expiresafe.db
    │   └── uploads/   (full copy)
    ├── 2026-02-05/
    └── 2026-02-06/

Usage:
  python backup.py              # run a backup now
  python backup.py --list       # list existing backups
  python backup.py --restore 2026-02-05  # restore from a date

Can also be imported and called from the Flask app.
"""

import os, sys, shutil, sqlite3, json
from datetime import datetime, timezone

APP_PATH = os.path.dirname(os.path.abspath(__file__))
PERSISTENT_DIR = os.environ.get("PERSISTENT_STORAGE_PATH", APP_PATH)

DB_PATH = os.path.join(PERSISTENT_DIR, "instance", "expiresafe.db")
UPLOADS_DIR = os.path.join(PERSISTENT_DIR, "uploads")
BACKUPS_DIR = os.path.join(PERSISTENT_DIR, "backups")


def _utcnow():
    return datetime.now(timezone.utc)


def run_backup(label=None):
    """
    Create a dated backup of the database and uploads folder.
    Returns dict with backup details.
    """
    today = label or _utcnow().strftime("%Y-%m-%d")
    backup_dir = os.path.join(BACKUPS_DIR, today)
    os.makedirs(backup_dir, exist_ok=True)

    result = {
        "date": today,
        "path": backup_dir,
        "db_backed_up": False,
        "db_size": 0,
        "uploads_backed_up": False,
        "upload_files": 0,
        "upload_size": 0,
    }

    # ── 1. Database backup (safe SQLite copy) ──
    db_dest = os.path.join(backup_dir, "expiresafe.db")
    if os.path.exists(DB_PATH):
        # Use SQLite backup API for a consistent copy (safe even while app is running)
        src_conn = sqlite3.connect(DB_PATH)
        dst_conn = sqlite3.connect(db_dest)
        src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()
        result["db_backed_up"] = True
        result["db_size"] = os.path.getsize(db_dest)

    # ── 2. Uploads folder backup ──
    uploads_dest = os.path.join(backup_dir, "uploads")
    if os.path.isdir(UPLOADS_DIR):
        # Remove old uploads backup for this date if re-running
        if os.path.isdir(uploads_dest):
            shutil.rmtree(uploads_dest)
        shutil.copytree(UPLOADS_DIR, uploads_dest)
        result["uploads_backed_up"] = True
        # Count files and total size
        for root, dirs, files in os.walk(uploads_dest):
            for f in files:
                fp = os.path.join(root, f)
                result["upload_files"] += 1
                result["upload_size"] += os.path.getsize(fp)

    # ── 3. Write manifest ──
    manifest = {
        "created_at": _utcnow().isoformat(),
        "db_size_bytes": result["db_size"],
        "upload_files": result["upload_files"],
        "upload_size_bytes": result["upload_size"],
    }
    with open(os.path.join(backup_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    return result


def list_backups():
    """Return a list of existing backups with metadata, newest first."""
    backups = []
    if not os.path.isdir(BACKUPS_DIR):
        return backups

    for name in sorted(os.listdir(BACKUPS_DIR), reverse=True):
        bdir = os.path.join(BACKUPS_DIR, name)
        if not os.path.isdir(bdir):
            continue

        manifest_path = os.path.join(bdir, "manifest.json")
        info = {"date": name, "path": bdir, "db_exists": False, "upload_files": 0}

        if os.path.exists(manifest_path):
            with open(manifest_path) as f:
                manifest = json.load(f)
            info["created_at"] = manifest.get("created_at", "")
            info["db_size"] = manifest.get("db_size_bytes", 0)
            info["upload_files"] = manifest.get("upload_files", 0)
            info["upload_size"] = manifest.get("upload_size_bytes", 0)

        info["db_exists"] = os.path.exists(os.path.join(bdir, "expiresafe.db"))
        info["uploads_exist"] = os.path.isdir(os.path.join(bdir, "uploads"))

        backups.append(info)

    return backups


def restore_backup(date_label):
    """
    Restore database and uploads from a dated backup.
    Returns dict describing what was restored.
    """
    backup_dir = os.path.join(BACKUPS_DIR, date_label)
    if not os.path.isdir(backup_dir):
        return {"error": f"Backup '{date_label}' not found"}

    result = {"date": date_label, "db_restored": False, "uploads_restored": False}

    # Restore DB
    db_src = os.path.join(backup_dir, "expiresafe.db")
    if os.path.exists(db_src):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        shutil.copy2(db_src, DB_PATH)
        result["db_restored"] = True

    # Restore uploads
    uploads_src = os.path.join(backup_dir, "uploads")
    if os.path.isdir(uploads_src):
        if os.path.isdir(UPLOADS_DIR):
            shutil.rmtree(UPLOADS_DIR)
        shutil.copytree(uploads_src, UPLOADS_DIR)
        result["uploads_restored"] = True

    return result


def _fmt_size(b):
    """Human-readable file size."""
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


# ── CLI ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    if "--list" in sys.argv:
        backups = list_backups()
        if not backups:
            print("No backups found.")
        else:
            print(f"{'Date':<14} {'Database':<14} {'Uploads':<20} {'Created'}")
            print("─" * 70)
            for b in backups:
                db_info = _fmt_size(b.get("db_size", 0)) if b.get("db_exists") else "—"
                up_info = f"{b.get('upload_files', 0)} files ({_fmt_size(b.get('upload_size', 0))})" if b.get("uploads_exist") else "—"
                created = b.get("created_at", "—")[:19]
                print(f"{b['date']:<14} {db_info:<14} {up_info:<20} {created}")

    elif "--restore" in sys.argv:
        idx = sys.argv.index("--restore")
        if idx + 1 >= len(sys.argv):
            print("Usage: python backup.py --restore 2026-02-05")
            sys.exit(1)
        date_label = sys.argv[idx + 1]
        confirm = input(f"⚠️  Restore from {date_label}? This will OVERWRITE current data. Type YES: ")
        if confirm.strip() != "YES":
            print("Aborted.")
            sys.exit(0)
        r = restore_backup(date_label)
        if "error" in r:
            print(f"❌ {r['error']}")
            sys.exit(1)
        print(f"✅ Restored from {date_label}")
        print(f"   Database: {'restored' if r['db_restored'] else 'not found in backup'}")
        print(f"   Uploads:  {'restored' if r['uploads_restored'] else 'not found in backup'}")

    else:
        print("Running backup...")
        r = run_backup()
        print(f"✅ Backup saved to: {r['path']}")
        print(f"   Database: {_fmt_size(r['db_size'])} {'✓' if r['db_backed_up'] else '✗'}")
        print(f"   Uploads:  {r['upload_files']} files ({_fmt_size(r['upload_size'])}) {'✓' if r['uploads_backed_up'] else '✗'}")
