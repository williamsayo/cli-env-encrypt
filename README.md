# CLI Environment Variable Encryption Script

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

### Options

| Option | Description |
|--------|-------------|
| `-e`, `--encrypt` | Encrypt the specified file |
| `-d`, `--decrypt` | Decrypt the specified file |
| `-p`, `--password` | Prompt for a password instead of using the default password |
| `-v`, `--version` | Display the script version |

### How It Works

1. **Encryption**  
   - Prompts for a password if `-p` is used.  
   - Adds a `.encrypted` extension to the file.
   - Saves a unique salt for the encryption key as `<filename>.salt`.

2. **Decryption**  
   - Prompts for a password if `-p` is used, otherwise uses the default.  
   - Validates that the file has a `.encrypted` extension.  
   - Restores the original environment file content.

### Help

The script includes a built-in help option to display usage instructions, available commands, and examples.

Use the following flags to access it:

**Run**

```bash
python env_encrypt_cli.py -h
```

**Output**
```bash
usage: main.py (-e | -d) [file]

Encrypt or decrypt environment variable files using a password.

positional arguments:
  file            File to encrypt/decrypt.

options:
  -h, --help      show this help message and exit
  -v, --version   show program's version number and exit
  -p, --password  Password to use for encryption/decryption.
  -e, --encrypt   To encrypt the file, only -e or --encrypt can be specified.
  -d, --decrypt   To decrypt the file, only -d or --decrypt can be specified.

Examples:
    main.py -e .env.local        Encrypt an environment file named .env.local
    main.py -d .env.local        Decrypt an environment file named .env.local
    main.py -e             Encrypt the default .env file
    main.py -d             Decrypt the default .env file
    main.py -e -p          Encrypt with a specified password
    main.py -d -p          Decrypt with a specified password

```

## Run Tests

```bash
uv run python -m unittest discover tests
```