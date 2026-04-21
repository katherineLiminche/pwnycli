import subprocess
import sqlite3
import shutil
import sys
from pathlib import Path
import os
BASE = Path(os.getenv("PWN_BASE", Path.home() / "pwnagotchi"))

INCOMING = BASE / "data/incoming"
GOOD = BASE / "data/good_pcaps"
BAD = BASE / "data/bad_pcaps"
HASHES = BASE / "data/hashes"

DB = BASE / "db/networks.db"

GOOD.mkdir(parents=True, exist_ok=True)
BAD.mkdir(parents=True, exist_ok=True)
HASHES.mkdir(parents=True, exist_ok=True)

DB.parent.mkdir(parents=True, exist_ok=True)
conn = sqlite3.connect(DB)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS captures(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT UNIQUE,
    bssid TEXT,
    ssid TEXT,
    password TEXT,
    handshake INTEGER,
    pmkid INTEGER,
    hashfile TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

try:
    for pcap in INCOMING.glob("*.pcap"):

        print(f"Analyzing {pcap.name}")
    
        hashfile = HASHES / (pcap.stem + ".22000")
        result = subprocess.run(
            [
                "hcxpcapngtool",
                str(pcap)
            ],
            capture_output=True,
            text=True
        )

        handshake = "eapol" in result.stdout.lower()
        pmkid = "pmkid" in result.stdout.lower()
        usable = handshake or pmkid

        c.execute(
            "INSERT OR IGNORE INTO captures(filename, handshake, pmkid, hashfile) VALUES(?,?,?,?)",
            (pcap.name, int(handshake), int(pmkid), None)  # hashfile filled in by 3_convert.py
        )
        if usable:
            print("  usable capture found")
            shutil.move(pcap, GOOD / pcap.name)
        else:
            print("  no authentication material")
            shutil.move(pcap, BAD / pcap.name)


        conn.commit()
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
finally:
    conn.close()

