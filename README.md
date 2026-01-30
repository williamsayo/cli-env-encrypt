# Env Encrypt CLI

A simple Python command-line tool to **encrypt and decrypt `.env` files** using a password. This allows you to securely share environment files without exposing sensitive information.

---

## Features

- Encrypt `.env` files with a password.
- Decrypt previously encrypted files.
- Password confirmation for encryption.
- Default `.env` file support.
- Supports specifying a password interactively.
- Provides helpful logging and error messages.

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/cli-env-encrypt.git
cd cli-env-encrypt
```

2. Install dependencies

```bash
uv install
```

## Usage

```bash
uv main.py [options] [file]
```

## Run Tests

```bash
uv run python -m unittest discover tests
```