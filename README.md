# SVault - Secure Vault CLI

**SVault** is a **secure, encrypted secrets manager** for storing passwords, API keys, SSH keys and other sensitive data.

---

## Features

* AES-GCM encryption for all secrets
* Argon2id password-based key derivation
* Vault stored locally in `~/.svault`
* Commands: `init`, `add`, `get`, `list`, `delete`, `remove`, `status`
* Clipboard support (`--clip`) with auto-clear (Linux/Mac)
* Vault lock to prevent concurrent edits
* Strict file permissions (`700` for folder, `600` for files)

---

## Installation

### 1. Clone repository

```bash
git clone https://github.com/<your-username>/svault.git
cd svault
```

### 2. Install Python dependencies

```bash
sudo apt update
sudo apt install python3-pip xclip
sudo apt install python3-cryptography python3-argon2 python3-rich python3-pyperclip
```

> Linux users need `xclip` or `xsel` for clipboard support.

### 3. Install CLI command

```bash
sudo cp vault.py /usr/local/bin/vault
sudo chmod +x /usr/local/bin/vault
```

> The script is now available system-wide as `vault`.

---

## Setup & Initialization

```bash
vault init
```

* Enter master password
* Confirm password

> Creates `~/.svault` with encrypted storage.

---

## Usage

### Add a secret

```bash
vault add <secret_name>
```

**Example:**

```bash
vault add github_token
```

---

### Get a secret

```bash
vault get <secret_name>
```

**Clipboard mode:**

```bash
vault get github_token --clip
```

---

### List stored secrets

```bash
vault list
```

---

### Delete a secret

```bash
vault delete <secret_name>
```

---

### Vault status

```bash
vault status
```

---

### Remove the entire vault

```bash
vault remove
```

> ⚠ Use carefully irreversible action.

---

## Security Notes

* Secrets are **encrypted at rest** using AES-GCM
* Master password is **never stored**
* Vault files have **strict permissions**
* **Concurrent access prevented** with lock file
* Clipboard secrets auto-clear to reduce exposure

---


## Tips

* Always use a **strong master password**
* Keep your vault folder **private**
* Backup `vault.enc` and `vault.meta` for disaster recovery
* Do not run as root unless necessary

---

## Example Workflow

```bash
vault init

vault add github_token
vault add aws_key

vault list

vault get github_token
vault get aws_key --clip

vault delete aws_key

vault status

vault remove
```

---

## Verification

```bash
which vault
# Should output: /usr/local/bin/vault

```
