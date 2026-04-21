import sqlite3
import sys
import subprocess
from pathlib import Path
import os

BASE = Path(os.getenv("PWN_BASE", Path.home() / "pwnagotchi"))
DB = BASE / "db/networks.db"
GOOD = BASE / "data/good_pcaps"
HASHES = BASE / "data/hashes"

HASHES.mkdir(parents=True, exist_ok=True)

print("Starting conversion...")

failed = 0 

for pcap in GOOD.glob("*.pcap"):

    hashfile = HASHES / (pcap.stem + ".22000")

    if hashfile.exists() and hashfile.stat().st_size > 0:
        print("Skipping (already converted):", pcap.name)
        continue

    print("Converting:", pcap.name)

    subprocess.run([
        "hcxpcapngtool",
        "-o",
        str(hashfile),
        str(pcap)
    ])

    if hashfile.exists() and hashfile.stat().st_size > 0:
        print("Hash created:", hashfile.name)
        conn = sqlite3.connect(DB)
        conn.execute(
            "UPDATE captures SET hashfile = ? WHERE filename = ?",
            (str(hashfile), pcap.name)
        )
        conn.commit()
        conn.close()
    else:
        print("No hash extracted from:", pcap.name)
        if hashfile.exists():
            hashfile.unlink()
        failed += 1
if failed:
    sys.exit(1)
print("Conversion complete")
