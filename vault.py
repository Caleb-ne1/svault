#!/usr/bin/env python3

import os
import json
import base64
import getpass
import argparse
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.text import Text

import pyperclip

# config

VAULT_DIR = os.path.expanduser("~/.svault")
META_FILE = os.path.join(VAULT_DIR, "vault.meta")
DATA_FILE = os.path.join(VAULT_DIR, "vault.enc")
LOCK_FILE = os.path.join(VAULT_DIR, "vault.lock")

KEY_LEN = 32
ARGON_TIME = 3
ARGON_MEMORY = 65536
ARGON_PARALLELISM = 2

CLIPBOARD_TIMEOUT = 15  # seconds

console = Console()

# ui

def banner():
    console.print(
        Text("🔐 SVault", style="bold cyan"),
        Text(" — Secure Secret Manager\n", style="dim")
    )

def info(msg): console.print(f"[cyan][*][/cyan] {msg}")
def success(msg): console.print(f"[green][✔][/green] {msg}")
def warning(msg): console.print(f"[yellow][!][/yellow] {msg}")
def error(msg): console.print(f"[red][✘][/red] {msg}")

# locking

def acquire_lock():
    if os.path.exists(LOCK_FILE):
        raise RuntimeError("Vault is already in use.")
    with open(LOCK_FILE, "w") as f:
        f.write(str(os.getpid()))

def release_lock():
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)

# utils

def ensure_permissions():
    os.makedirs(VAULT_DIR, exist_ok=True)
    os.chmod(VAULT_DIR, 0o700)

def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        password.encode(),
        salt,
        ARGON_TIME,
        ARGON_MEMORY,
        ARGON_PARALLELISM,
        KEY_LEN,
        Type.ID,
    )

def encrypt_data(key: bytes, data: dict) -> bytes:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(data).encode()
    return nonce + aes.encrypt(nonce, plaintext, None)

def decrypt_data(key: bytes, blob: bytes) -> dict:
    aes = AESGCM(key)
    nonce, ciphertext = blob[:12], blob[12:]
    return json.loads(aes.decrypt(nonce, ciphertext, None).decode())

def load_meta():
    with open(META_FILE) as f:
        return json.load(f)

def save_meta(meta):
    with open(META_FILE, "w") as f:
        json.dump(meta, f, indent=2)
    os.chmod(META_FILE, 0o600)

# core

def open_vault():
    acquire_lock()

    if not os.path.exists(DATA_FILE):
        release_lock()
        raise RuntimeError("Vault not initialized.")

    meta = load_meta()
    salt = base64.b64decode(meta["salt"])
    password = getpass.getpass("Master password: ")
    key = derive_key(password, salt)

    try:
        with open(DATA_FILE, "rb") as f:
            data = decrypt_data(key, f.read())
    except Exception:
        release_lock()
        raise RuntimeError("Invalid password or corrupted vault.")

    return data, key

def save_vault(data, key):
    with open(DATA_FILE, "wb") as f:
        f.write(encrypt_data(key, data))
    os.chmod(DATA_FILE, 0o600)
    release_lock()

# commands

def cmd_init():
    banner()
    if os.path.exists(DATA_FILE):
        warning("Vault already exists.")
        return

    ensure_permissions()
    pw = getpass.getpass("Set master password: ")
    if pw != getpass.getpass("Confirm password: "):
        error("Passwords do not match.")
        return

    salt = os.urandom(16)
    key = derive_key(pw, salt)

    save_meta({
        "version": 1,
        "kdf": "argon2id",
        "salt": base64.b64encode(salt).decode(),
        "created": datetime.now(timezone.utc).isoformat()
    })

    with open(DATA_FILE, "wb") as f:
        f.write(encrypt_data(key, {}))
    os.chmod(DATA_FILE, 0o600)

    success("Vault initialized.")

def cmd_add(name):
    banner()
    data, key = open_vault()

    if name in data:
        warning("Secret already exists.")
        release_lock()
        return

    secret = getpass.getpass("Secret value: ")
    data[name] = {
        "value": secret,
        "created": datetime.now(timezone.utc).isoformat()
    }

    save_vault(data, key)
    success(f"Secret '{name}' added.")

def cmd_get(name, clip):
    banner()
    data, _ = open_vault()

    if name not in data:
        release_lock()
        error("Secret not found.")
        return

    value = data[name]["value"]
    release_lock()

    if clip:
        pyperclip.copy(value)
        success(f"Copied to clipboard (clears in {CLIPBOARD_TIMEOUT}s).")
        time.sleep(CLIPBOARD_TIMEOUT)
        pyperclip.copy("")
    else:
        console.print(value, style="bold")

# list command 
def cmd_list():
    banner()
    data, _ = open_vault()

    if not data:
        release_lock()
        info("Vault is empty.")
        return

    table = Table(title="Stored Secrets", header_style="bold cyan")
    table.add_column("Name")
    table.add_column("Created", style="dim")

    for k, v in data.items():
        table.add_row(k, v["created"])

    release_lock()
    console.print(table)

# status command for vault
def cmd_status():
    banner()
    table = Table(title="Vault Status")
    table.add_column("Check")
    table.add_column("Result")

    table.add_row("Vault exists", "✔" if os.path.exists(DATA_FILE) else "✘")
    table.add_row("Permissions", "✔" if oct(os.stat(DATA_FILE).st_mode)[-3:] == "600" else "⚠")
    table.add_row("KDF", "Argon2id")
    table.add_row("Memory", f"{ARGON_MEMORY} KB")

    console.print(table)


# remove command for vault
def cmd_remove():
    banner()
    try:
        open_vault()
    except RuntimeError:
        error("Invalid password.")
        return

    confirm = Prompt.ask(
        "[red]This will permanently delete the vault. Continue?[/red]",
        choices=["y", "n"],
        default="n"
    )

    if confirm != "y":
        release_lock()
        info("Aborted.")
        return

    for f in [DATA_FILE, META_FILE, LOCK_FILE]:
        if os.path.exists(f):
            os.remove(f)

    try:
        os.rmdir(VAULT_DIR)
    except OSError:
        pass

    success("Vault removed.")

# delete command secret
def cmd_delete(name: str):
    """
    Delete a single secret from the vault.
    """
    banner()
    try:
        data, key = open_vault()
    except RuntimeError as e:
        error(str(e))
        return

    if name not in data:
        release_lock()
        error(f"Secret '{name}' not found.")
        return

    confirm = Prompt.ask(
        f"[red]Are you sure you want to delete '{name}'?[/red]",
        choices=["y", "n"],
        default="n"
    )

    if confirm != "y":
        release_lock()
        info("Deletion aborted.")
        return

    del data[name]
    save_vault(data, key)
    success(f"Secret '{name}' deleted.")


# cli

def main():
    parser = argparse.ArgumentParser(description="SVault")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("init")

    add = sub.add_parser("add")
    add.add_argument("name")

    get = sub.add_parser("get")
    get.add_argument("name")
    get.add_argument("--clip", action="store_true")

    delete = sub.add_parser("delete")
    delete.add_argument("name")


    sub.add_parser("list")
    sub.add_parser("status")
    sub.add_parser("remove")

    args = parser.parse_args()

    try:
        if args.cmd == "init": cmd_init()
        elif args.cmd == "add": cmd_add(args.name)
        elif args.cmd == "get": cmd_get(args.name, args.clip)
        elif args.cmd == "list": cmd_list()
        elif args.cmd == "status": cmd_status()
        elif args.cmd == "remove": cmd_remove()
        elif args.cmd == "delete": cmd_delete(args.name)
        else: parser.print_help()
    except RuntimeError as e:
        error(str(e))
        exit(1)

if __name__ == "__main__":
    main()

