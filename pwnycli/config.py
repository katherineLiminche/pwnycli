from __future__ import annotations

import os
import json
from pathlib import Path

BASE = Path(os.getenv("PWN_BASE", Path.home() / "pwnagotchi"))
CONFIG_FILE = BASE / "config.json"

DEFAULT_CONFIG = {
    "remote_host": "",
    "remote_user": "",
    "remote_dir": "/home/pi/handshakes",
    "ssh_port": 22,
    "ssh_key": ""
}


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            return {**DEFAULT_CONFIG, **data}
        except json.JSONDecodeError:
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()


def save_config(cfg: dict) -> None:
    BASE.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def configure(force: bool = False) -> dict:
    cfg = load_config()

    if force or not CONFIG_FILE.exists():
        print("Configure Pwnagotchi transfer credentials\n")

        host = input(f"Remote host [{cfg['remote_host']}]: ").strip()
        if host:
            cfg["remote_host"] = host

        user = input(f"Remote user [{cfg['remote_user']}]: ").strip()
        if user:
            cfg["remote_user"] = user

        remote_dir = input(f"Remote dir [{cfg['remote_dir']}]: ").strip()
        if remote_dir:
            cfg["remote_dir"] = remote_dir

        port = input(f"SSH port [{cfg['ssh_port']}]: ").strip()
        if port:
            try:
                cfg["ssh_port"] = int(port)
            except ValueError:
                print(f"Invalid port '{port}', keeping current value: {cfg['ssh_port']}")

        ssh_key = input(f"SSH key path [{cfg['ssh_key']}]: ").strip()
        if ssh_key:
            cfg["ssh_key"] = ssh_key

        save_config(cfg)
        print(f"Saved: {CONFIG_FILE}")

    return cfg


def ensure_config() -> dict:
    cfg = load_config()

    if not cfg["remote_host"] or not cfg["remote_user"]:
        cfg = configure(force=True)

    return cfg
