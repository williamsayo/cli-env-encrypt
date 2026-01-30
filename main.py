import sys
import getpass
import logging
from typing import Literal, TypeAlias

CommandType: TypeAlias = Literal["DECRYPT", "ENCRYPT"]
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

def getPassword(command: CommandType) -> str:
    if command == "ENCRYPT":
        while True:
            password = getpass.getpass(f"Enter the password for encrypting: ")
            # Ensure the password meets minimum length requirements
            if len(password) < 8:
                logger.error("Password is too short. Please enter a password with at least 8 characters.")
                continue
            confirm_password = getpass.getpass("Confirm the password: ")
            # Check if the passwords match
            if password == confirm_password:
                break
            else:
                logger.error(
                    "Passwords do not match or are too short. Please try again."
                )
    else:
        password = getpass.getpass("Enter the password for decrypting: ")

    return password

def validateFile(fileName: str, command: CommandType) -> bool:
    fileExtension = fileName.split(".").pop()
    if command == 'ENCRYPT' and fileExtension == "encrypted":
        logger.error("File already encrypted.")
    elif command == "DECRYPT" and fileExtension != "encrypted":
        logger.error("File was not encrypted. Encrypted file has a .encrypted extension")
    else:
        return
    sys.exit(1)

def main():
    from argparse import ArgumentParser, Namespace, RawDescriptionHelpFormatter
    from encryptionHelper import EncryptionHelper

    encryption_helper = EncryptionHelper()
    defaultPaassword = "default_password_123"  # Replace with a secure default password or method to retrieve it

    descriptionEpilog: str = """
Examples:
    %(prog)s -e .env.local        Encrypt an environment file named .env.local
    %(prog)s -d .env.local        Decrypt an environment file named .env.local
    %(prog)s -e             Encrypt the default .env file
    %(prog)s -d             Decrypt the default .env file
    %(prog)s -e -p          Encrypt with a specified password
    %(prog)s -d -p          Decrypt with a specified password
    """

    parser = ArgumentParser(
        description="Encrypt or decrypt environment variable files using a password.",
        usage="%(prog)s (-e | -d) [file]",
        epilog=descriptionEpilog,
        formatter_class=RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument(
        "-v", '--version', action='version', version='%(prog)s 1.0'
    )
    groupArgs = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument(
        "file", help="File to encrypt/decrypt.", default=".env", type=str, nargs="?"
    )
    parser.add_argument(
        "-p", '--password', action='store_true', help="Password to use for encryption/decryption.", required=False
    )

    groupArgs.add_argument(
        "-e",
        "--encrypt",
        action="store_true",
        help="To encrypt the file, only -e or --encrypt can be specified.",
    )
    groupArgs.add_argument(
        "-d",
        "--decrypt",
        action="store_true",
        help="To decrypt the file, only -d or --decrypt can be specified.",
    )

    args: Namespace = parser.parse_args()
    fileName:str = args.file

    try:
        with open(fileName, "r", encoding="utf-8") as envFile:
            envFileContent = envFile.read()

        # Check if the file is empty
        if not envFileContent:
            logger.warning(f"The file '{args.file}' is empty.")
            sys.exit(0)

        # Perform encryption based on the provided arguments
        if args.encrypt:
            command: CommandType = "ENCRYPT"
            validateFile(fileName, command)
            encryptionPassword = getPassword(command) if args.password else defaultPaassword
            key = encryption_helper.generate_key(
                encryptionPassword, fileName, save_salt=True
            )
            encryption_helper.encrypt(fileName, key)
        # Perform decryption based on the provided arguments
        elif args.decrypt:
            command: CommandType = "DECRYPT"
            validateFile(fileName, command)
            decryptionPassword = (
                getPassword(command) if args.password else defaultPaassword
            )
            key = encryption_helper.generate_key(
                decryptionPassword, fileName, load_existing_salt=True
            )
            encryption_helper.decrypt(fileName, key)

    # Handle the case where the specified file does not exist
    except FileNotFoundError:
        logger.error(f"The file '{args.file}' does not exist.")

if __name__ == "__main__":
    main()
