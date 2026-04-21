#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
import sqlite3
import shutil
import time
import glob
from pathlib import Path

BASE = Path(os.getenv("PWN_BASE", Path.home() / "pwnagotchi"))

SCRIPTS_DIR = Path(__file__).parent / "scripts"

SCRIPTS = {
    "transfer": SCRIPTS_DIR / "1_transfer.py",
    "analyze":  SCRIPTS_DIR / "2_analyze.py",
    "convert":  SCRIPTS_DIR / "3_convert.py",
    "crack":    SCRIPTS_DIR / "4_crack.py",
    "cleanup":  SCRIPTS_DIR / "5_cleanup.py",
}

PIPELINE = ["transfer", "analyze", "convert", "crack", "cleanup"]

DATA = BASE / "data"
DB = BASE / "db/networks.db"


def run_script(name):
    script = SCRIPTS[name]

    if not script.exists():
        print(f"Missing script: {script}")
        sys.exit(1)

    print(f"\n=== {name} ===")

    subprocess.run(
        [sys.executable, str(script)],
        check=True
    )


def run_pipeline():
    for step in PIPELINE:
        run_script(step)

def init():
    dirs = [
        DATA / "incoming",
        DATA / "good_pcaps",
        DATA / "bad_pcaps",
        DATA / "hashes",
        BASE / "db",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        print(f"[OK] {d}")

    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS captures (
            id       INTEGER PRIMARY KEY,
            ssid     TEXT,
            bssid    TEXT,
            password TEXT,
            seen_at  TEXT
        )
    """)
    conn.commit()
    conn.close()
    print("[OK] database")

def doctor():
    print("Running diagnostics\n")

    tools = ["ssh", "scp", "hashcat", "hcxpcapngtool"]

    for tool in tools:
        if shutil.which(tool):
            print(f"[OK] {tool}")
        else:
            print(f"[MISSING] {tool}")

    print()

    dirs = [
        DATA / "incoming",
        DATA / "good_pcaps",
        DATA / "bad_pcaps",
        DATA / "hashes"
    ]

    for d in dirs:
        if d.exists():
            print(f"[OK] {d}")
        else:
            print(f"[MISSING] {d}")

    print()

    if DB.exists():
        print("[OK] database")
    else:
        print("[MISSING] database")


def status():
    incoming = len(list((DATA / "incoming").glob("*.pcap")))
    good     = len(list((DATA / "good_pcaps").glob("*.pcap")))
    bad      = len(list((DATA / "bad_pcaps").glob("*.pcap")))
    hashes   = len(list((DATA / "hashes").glob("*.22000")))

    print("Pipeline status\n")
    print(f"incoming pcaps : {incoming}")
    print(f"good pcaps     : {good}")
    print(f"bad pcaps      : {bad}")
    print(f"hashes         : {hashes}")


def stats():
    if not DB.exists():
        print("Database not found")
        return

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM captures")
    total = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM captures WHERE password IS NOT NULL")
    cracked = cur.fetchone()[0]

    conn.close()

    rate = (cracked / total * 100) if total else 0

    print("\nNetwork statistics\n")
    print(f"total networks : {total}")
    print(f"cracked        : {cracked}")
    print(f"success rate   : {rate:.2f}%")


def loop(delay):
    print("Starting loop mode\n")
    while True:
        run_pipeline()
        print(f"\nsleeping {delay} seconds\n")
        time.sleep(delay)


def watch():
    print("Watching pipeline (Ctrl+C to exit)\n")

    while True:
        incoming = len(list((DATA / "incoming").glob("*.pcap")))
        good     = len(list((DATA / "good_pcaps").glob("*.pcap")))
        bad      = len(list((DATA / "bad_pcaps").glob("*.pcap")))
        hashes   = len(list((DATA / "hashes").glob("*.22000")))
        cracked  = 0

        if DB.exists():
            conn = sqlite3.connect(DB)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM captures WHERE password IS NOT NULL")
            cracked = cur.fetchone()[0]
            conn.close()

        print(
            f"\rincoming:{incoming}  good:{good}  bad:{bad}  hashes:{hashes}  cracked:{cracked}",
            end="",
            flush=True
        )

        time.sleep(5)


def purge():
    print("Purging broken files\n")
    removed = 0

    for hashfile in (DATA / "hashes").glob("*.22000"):
        if hashfile.stat().st_size == 0:
            print("Removing empty hash:", hashfile.name)
            hashfile.unlink()
            removed += 1

    for pcap in (DATA / "good_pcaps").glob("*.pcap"):
        hashfile = DATA / "hashes" / (pcap.stem + ".22000")
        if not hashfile.exists():
            print("Removing orphan capture:", pcap.name)
            pcap.unlink()
            removed += 1

    print(f"\nRemoved {removed} files")


def export():
    if not DB.exists():
        print("Database not found")
        return

    outfile = BASE / "cracked_networks.txt"

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT ssid, password FROM captures WHERE password IS NOT NULL")
    rows = cur.fetchall()
    conn.close()

    with open(outfile, "w") as f:
        for ssid, password in rows:
            f.write(f"{ssid or 'unknown'}:{password}\n")

    print(f"Exported {len(rows)} networks → {outfile}")


def bench():
    print("Running hashcat benchmark\n")
    subprocess.run(["hashcat", "-b", "-m", "22000"])


def autopwn():
    if not DB.exists():
        print("Database not found")
        return

    print("Generating smart wordlist")

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT ssid FROM captures WHERE password IS NULL")
    ssids = [row[0] for row in cur.fetchall() if row[0]]
    conn.close()

    wordlist = BASE / "tmp_autopwn.txt"
    words = set()

    for ssid in ssids:
        base  = ssid.lower()
        clean = base.replace("-", "").replace("_", "")

        words.add(base)
        words.add(clean)

        for year in ["2024", "2025", "2026"]:
            words.add(base + year)
            words.add(clean + year)

        for num in ["123", "1234", "12345"]:
            words.add(base + num)
            words.add(clean + num)

    filtered = [w for w in words if len(w) >= 8]

    with open(wordlist, "w") as f:
        for w in filtered:
            f.write(w + "\n")

    print(f"Generated {len(filtered)} candidates")

    hash_files = glob.glob(str(DATA / "hashes" / "*.22000"))

    if not hash_files:
        print("No hash files found")
        return

    subprocess.run(["hashcat", "-m", "22000", *hash_files, str(wordlist)])


def main():
    parser = argparse.ArgumentParser(
        description="Pwnagotchi cracking pipeline controller"
    )

    parser.add_argument(
        "command",
        choices=[
            "run",
            "transfer",
            "analyze",
            "convert",
            "crack",
            "cleanup",
            "doctor",
            "status",
            "stats",
            "watch",
            "purge",
            "export",
            "bench",
            "autopwn",
            "init",
        ]
    )

    parser.add_argument("--loop",  action="store_true")
    parser.add_argument("--delay", type=int, default=300)

    args = parser.parse_args()

    if args.command == "run":
        if args.loop:
            loop(args.delay)
        else:
            run_pipeline()

    elif args.command in SCRIPTS:
        run_script(args.command)

    elif args.command == "doctor":  doctor()
    elif args.command == "status":  status()
    elif args.command == "stats":   stats()
    elif args.command == "watch":   watch()
    elif args.command == "purge":   purge()
    elif args.command == "export":  export()
    elif args.command == "bench":   bench()
    elif args.command == "autopwn": autopwn()
    elif args.command == "init": init()

if __name__ == "__main__":
    main()
