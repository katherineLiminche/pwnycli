import sqlite3
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta

BASE = Path(os.getenv("PWN_BASE", Path.home() / "pwnagotchi"))
GOOD = BASE / "data/good_pcaps"
BAD = BASE / "data/bad_pcaps"
HASHES = BASE / "data/hashes"
DB = BASE / "db/networks.db"

BAD_RETENTION_DAYS = int(os.getenv("PWN_BAD_RETENTION_DAYS", 7))

conn = sqlite3.connect(DB)
cur = conn.cursor()

try:
    print("Starting cleanup...")
    removed = 0

    # Remove old bad pcaps
    limit = datetime.now() - timedelta(days=BAD_RETENTION_DAYS)

    for pcap in BAD.glob("*.pcap"):
        mtime = datetime.fromtimestamp(pcap.stat().st_mtime)
        if mtime < limit:
            print("Removing old bad capture:", pcap.name)
            pcap.unlink()
            removed += 1

    # Remove files where password was found
    cur.execute("SELECT filename FROM captures WHERE password IS NOT NULL")
    rows = cur.fetchall()

    for row in rows:
        filename = row[0]

        pcap_file = GOOD / filename
        hash_file = HASHES / (Path(filename).stem + ".22000")

        if pcap_file.exists():
            print("Removing cracked pcap:", filename)
            pcap_file.unlink()
            removed += 1

        if hash_file.exists():
            print("Removing cracked hash:", hash_file.name)
            hash_file.unlink()
            removed += 1

    print(f"Cleanup complete — {removed} files removed")

except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
finally:
    conn.close()
