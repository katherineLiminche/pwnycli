import subprocess
import sqlite3
import sys
import os
from pathlib import Path

BASE = Path(os.getenv("PWN_BASE", Path.home() / "pwnagotchi"))
GOOD = BASE / "data/good_pcaps"
HASHES = BASE / "data/hashes"
DB = BASE / "db/networks.db"
WORDLIST_DIR = Path(os.getenv("PWN_WORDLIST_DIR", Path.home() / "wordlists"))
RULE_DIR = WORDLIST_DIR / "rules"

WORDLISTS = [
    WORDLIST_DIR / "rockyou.txt",
    WORDLIST_DIR / "probable-v2-top12000.txt",
    WORDLIST_DIR / "kaonashi.txt",
]
RULES = [
    RULE_DIR / "best64.rule",
    RULE_DIR / "OneRuleToRuleThemAll.rule",
]
MASKS = [
    "?d?d?d?d?d?d?d?d",
    "?d?d?d?d?d?d?d?d?d",
    "?l?l?l?l?l?l?l?l",
    "?l?l?l?l?l?l?l?l?d?d",
]

BASE_FLAGS = [
    "-m", "22000",
    "-w", "4",
    "--quiet",
    "--force",
]

def run_hashcat(args: list[str]) -> int:
    result = subprocess.run(["hashcat"] + BASE_FLAGS + args)
    return result.returncode

def get_cracked_password(hashfile: Path) -> str | None:
    result = subprocess.run(
        ["hashcat", "-m", "22000", "--show", "--outfile-format", "2", str(hashfile)],
        capture_output=True, text=True,
    )
    line = result.stdout.strip()
    if line:
        return line.splitlines()[-1]
    return None

DB.parent.mkdir(parents=True, exist_ok=True)
conn = sqlite3.connect(DB)
cur = conn.cursor()

try:
    for pcap in GOOD.glob("*.pcap"):
        hashfile = HASHES / (pcap.stem + ".22000")

        cur.execute("SELECT password FROM captures WHERE filename=?", (pcap.name,))
        row = cur.fetchone()
        if row and row[0]:
            continue

        if not hashfile.exists() or hashfile.stat().st_size == 0:
            continue

        cracked = False

        # Stage 1 — wordlists
        for wl in WORDLISTS:
            if not wl.exists():
                continue
            print(f"[*] Wordlist: {wl.name}")
            run_hashcat([str(hashfile), str(wl)])
            if get_cracked_password(hashfile):
                cracked = True
                break

        # Stage 2 — rules (only if not cracked)
        if not cracked:
            for wl in WORDLISTS:
                if not wl.exists():
                    continue
                for rule in RULES:
                    if not rule.exists():
                        continue
                    print(f"[*] Rule: {wl.name} + {rule.name}")
                    run_hashcat([str(hashfile), str(wl), "-r", str(rule)])
                    if get_cracked_password(hashfile):
                        cracked = True
                        break
                if cracked:
                    break

        # Stage 3 — masks (only if not cracked)
        if not cracked:
            for mask in MASKS:
                print(f"[*] Mask: {mask}")
                run_hashcat([str(hashfile), "-a", "3", mask])
                if get_cracked_password(hashfile):
                    break

        # Save result
        password = get_cracked_password(hashfile)
        if password:
            print(f"[+] Found: {password}")
            cur.execute(
                "UPDATE captures SET hashfile=?, password=? WHERE filename=?",
                (str(hashfile), password, pcap.name),
            )
            conn.commit()

except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
finally:
    conn.close()
