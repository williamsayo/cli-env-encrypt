import sys
import getpass
import logging
from typing import Literal, TypeAlias
from dbStore import DB
from pathlib import Path
from argparse import ArgumentParser, Namespace, RawDescriptionHelpFormatter

CommandType: TypeAlias = Literal["DECRYPT", "ENCRYPT"]

def createLogger() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="[{levelname}]: {message}",
        style="{",
    )
    return logging.getLogger(__name__)

def getPassword(logger:logging.Logger,command: CommandType,passwordArg:bool) -> str:
    defaultPassword = "default_password_123"  # Replace with a secure default password or method to retrieve it
    if not passwordArg:
        password = defaultPassword
    elif passwordArg and command == "ENCRYPT":
        while True:
            password = getpass.getpass("Enter the password for encrypting: ")
            # Ensure the password meets minimum length requirements
            if not len(password) > 8:
                logger.error(
                    "Password is too short. Please enter a password with at least 8 characters."
                )
                continue
            confirm_password = getpass.getpass("Confirm the password: ")
            # Check if the passwords match
            if not password == confirm_password:
                logger.error(
                    "Passwords do not match. Please try again."
                )
                continue
    
            break
    else:
        password = getpass.getpass("Enter the password for decrypting: ")

    return password

def validateFile(fileName: str, command: CommandType) -> None:
    fileExtension = Path(fileName).suffix
    if command == "ENCRYPT" and fileExtension == ".encrypted":
        raise FileNotFoundError("File already encrypted.")
    elif command == "DECRYPT" and fileExtension != ".encrypted":
        raise FileNotFoundError("File was not encrypted. Encrypted file has a .encrypted extension.")

def createParser() -> ArgumentParser:
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
    parser.add_argument("-v", "--version", action="version", version="%(prog)s 1.0")
    groupArgs = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument(
        "file", help="File to encrypt/decrypt.", default=".env", type=str, nargs="?"
    )
    parser.add_argument(
        "-p",
        "--password",
        action="store_false",
        help="Password to use for encryption/decryption.",
        required=False,
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
    
    return parser

def main() -> None:
    from encryptionHelper import EncryptionHelper, EncryptionException, EncryptionLogger

    logger = createLogger()
    args: Namespace = createParser().parse_args()
    fileName: str = args.file
    passwordArg = args.password
    db = DB()
    encryptionHelper = EncryptionHelper(db, EncryptionLogger(logger), fileName)

    try:
        with Path(fileName).open("rb") as envFile:
            envFileContent = envFile.read()

        # Check if the file is empty
        if not envFileContent:
            raise EncryptionException.NoFileContent(
                f"The file '{args.file}' is empty."
            )

        # Perform encryption based on the provided arguments
        if args.encrypt:
            command: CommandType = "ENCRYPT"
            validateFile(fileName, command)
            encryptionPassword = getPassword(logger,command, passwordArg)
            encryptionHelper.encrypt(encryptionPassword)

        # Perform decryption based on the provided arguments
        elif args.decrypt:
            command = "DECRYPT"
            validateFile(fileName, command)
            decryptionPassword = getPassword(logger,command, passwordArg)
            encryptionHelper.decrypt(decryptionPassword)
    # Handle the case where the specified file does not exist
    except (
        EncryptionException.FileNotFound,
        FileNotFoundError,
        EncryptionException.IncorrectPassword,
    ) as errorMessage:
        logger.error(errorMessage)
    except KeyboardInterrupt:
        logger.critical("Encryption operation cancelled by user.")
    finally:
        db.close()
        sys.exit(1)

if __name__ == "__main__":
    main()
