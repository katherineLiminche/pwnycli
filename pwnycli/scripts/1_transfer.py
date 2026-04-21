import subprocess
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import ensure_config

cfg = ensure_config()

REMOTE_HOST = cfg["remote_host"]
REMOTE_USER = cfg["remote_user"]
REMOTE_DIR = cfg["remote_dir"]
SSH_PORT = cfg["ssh_port"]
SSH_KEY = cfg["ssh_key"]

BASE = Path(os.getenv("PWN_BASE", Path.home() / "pwnagotchi"))
LOCAL_DIR = BASE / "data/incoming"
LOCAL_DIR.mkdir(parents=True, exist_ok=True)

ssh_cmd = ["ssh", "-p", str(SSH_PORT)]
if SSH_KEY:
    ssh_cmd.extend(["-i", SSH_KEY])

print("Syncing pcaps from pwnagotchi...")

cmd = [
    "rsync",
    "-avz",
    "--remove-source-files",
    "-e", " ".join(f'"{a}"' if " " in a else a for a in ssh_cmd),
    f"{REMOTE_USER}@{REMOTE_HOST}:{REMOTE_DIR}/",
    str(LOCAL_DIR) + "/",
]

result = subprocess.run(cmd)

if result.returncode == 0:
    print("Transfer complete")
else:
    print("Transfer failed")
    sys.exit(1)
