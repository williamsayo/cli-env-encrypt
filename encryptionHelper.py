import base64
import secrets
from typing import Literal,Tuple
import uuid
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import cryptography
from dbStore import DB
from pathlib import Path
from logging import Logger

class EncryptionLogger:
    """
    A class to handle logging for EncryptionHelper.

    Methods
    -------
    log_error(message: str) -> None
        Logs an error message.
    FileNotFound(message: str) -> None
        Raises a FileNotFoundError with the given message.
    IncorrectPassword(message: str) -> None
        Raises an IncorrectPassword exception with the given message.
    """

    def __init__(self, logger: Logger) -> None:
        self.logger = logger

    def log_error(self, message: str) -> None:
        """Log an error message using the logger."""
        self.logger.error(message)

    def log_info(self, message: str) -> None:
        """Log an info message using the logger."""
        self.logger.info(message)


class EncryptionException(BaseException):
    ...
    class UnsupportedVersion(Exception):
        def __init__(self, version:str | None = None):
            errorMessage = (
                f"Unsupported encryption version: {version}"
                if version is not None
                else "Unsupported encryption version."
            )
            super().__init__(errorMessage)

    class FileNotFound(Exception):
        def __init__(self, errorMessage:str = "Encryption/Decryption File not found."):
            super().__init__(errorMessage)

    class IncorrectPassword(Exception):
        def __init__(
            self, errorMessage: str = "Invalid token, likely the password is incorrect."
        ):
            super().__init__(errorMessage)

    """Custom exception for EncryptionHelper errors."""

class EncryptionHelper:
    VERSION = "1.0"
    MAGIC = b"ENVENC"
    """
    A class to represent Encryption and Decryption of files.

    Methods
    -------
    load_salt(self, filename):
        A method to read and return a generated salt saved in file.
    derive_key(self, salt, password):
        A method to derive key.
    generate_key(self, password, filename, load_existing_salt=False, save_salt=False):
        A method to generate key.
    encrypt(self, filename, key):
        A method to encrypt file.
    decrypt(self, filename, key):
        A method to decrypt file.
    """

    def __init__(self, saltStore: DB, encryptionLogger: EncryptionLogger) -> None:
        self.saltStore = saltStore
        self.logger = encryptionLogger

    def createMetadata(self, salt: bytes) -> uuid.UUID:
        """
        A method to create metadata for the encrypted file, which includes a key to access salt from the database.
        """

        fileKey = uuid.uuid4()
        self.saltStore.save_salt(fileKey, salt)

        # metaData = '%s %s'%(self.VERSION,fileKey)

        return fileKey

    def readMetadata(self, fileName: str) -> uuid.UUID:
        """
        A method to read metadata from the encrypted file.
        """

        try:
            with Path(fileName).open("rb") as file:
                # Read the first line containing metadata
                metadataBytes = file.readline().strip()

            # if version != self.VERSION:
            #     raise EncryptionException.UnsupportedVersion()

            return uuid.UUID(bytes=metadataBytes)

        except FileNotFoundError:
            raise EncryptionException.FileNotFound("File not found")

    def loadSalt(self, fileKey: uuid.UUID) -> bytes:
        """
        A method to read and return a save salt file.

        Parameters
        ----------
        filename : str
            The file name to read from.

        Returns
        -------
        bytes
            The method returns bytes containing the salt.
        """
        try:
            salt = self.saltStore.get_salt(fileKey)
        except KeyError:
            raise EncryptionException.FileNotFound(
                "Salt not found for the given file key"
            )

        return salt[0]

    def generateKey(
        self,
        password: str,
        filename: str,
        save_salt: bool = False,
        load_existing_salt: bool = False,
    ) -> Tuple[bytes, bytes]:
        """
        A method to generate key.

        Parameters
        ----------
        password : str
            The strings of characters containing the password.
        filename : str
            The strings of characters containing file name.
        load_existing_salt : bool, optional
            A boolean value determining existing  salt exists.
        save_salt : bool, optional
            A boolean value determining save salt exists.

        Returns
        -------
        bytes
            The method returns bytes string containing the generated key.
        """

        # check existing salt file
        if load_existing_salt:
            # load existing salt
            metadata = self.readMetadata(filename)
            salt = self.loadSalt(metadata)

        if save_salt:
            # generate new salt/token and save it to file
            salt = EncryptionHelper.generateSalt(16)

            # create metadata and save salt to database
            metadata = self.createMetadata(salt)

        # generate the key from the salt and the password
        derived_key = EncryptionHelper.deriveKey(salt, password)

        # encode it using Base 64 and return it
        return base64.urlsafe_b64encode(derived_key), metadata.bytes

    def encrypt(self, encryptionPassword: str, filename: str) -> str:
        """
        A method to encrypt file.

        Parameters
        ----------
        filename : str
            The strings of characters containing file name.
        key : bytes
            A bytes of stings containing the encryption key.

        Returns
        -------
        None
            The method returns a none value.
        """

        key, metadata = self.generateKey(
            password=encryptionPassword, filename=filename, save_salt=True
        )
        fernet, fileData = EncryptionHelper.readFileAndCreateFernet(filename, key)

        # encrypting file_data
        encryptedData = fernet.encrypt(fileData)

        # writing to a new file with the encrypted data
        with Path(f"{filename}.encrypted").open("wb") as encryptedFile:
            encryptedFile.writelines([metadata, b"\n", encryptedData])

        # delete original file after encrypting file
        Path.unlink(Path(filename))

        self.logger.log_info("File encrypted successfully...")
        return "File encrypted successfully..."

    def decrypt(self, decryptionPassword: str, filename: str) -> str:
        """
        A method to decrypt file.

        Parameters
        ----------
        filename : str
            The strings of characters containing file name.
        key : bytes
            A bytes of stings containing the encryption key.

        Returns
        -------
        None
            The method returns a none value.
        """

        key, _ = self.generateKey(
            password=decryptionPassword, filename=filename, load_existing_salt=True
        )

        fernet, encryptedData = EncryptionHelper.readFileAndCreateFernet(
            filename, key, command="DECRYPT"
        )

        # decrypt data using the Fernet object
        try:
            decryptedData = fernet.decrypt(encryptedData)

        except cryptography.fernet.InvalidToken:
            raise EncryptionException.IncorrectPassword(
                "Invalid token, likely the password is incorrect."
            )

        # write the original file with decrypted content
        with Path(filename.replace(".encrypted", "")).open("wb") as file:
            file.write(decryptedData)

        # cleanup: delete salt from database
        self.saltStore.delete_salt(self.readMetadata(filename))

        # delete decrypted file
        Path.unlink(Path(filename))

        self.logger.log_info("File decrypted successfully...")
        return "File decrypted successfully..."

    @staticmethod
    def generateSalt(size: int) -> bytes:
        """
        A method to generate a salt.

        Parameters
        ----------
        size : int
            The size of the bytes strings to be generated.

        Returns
        -------
        bytes
            The method returns bytes strings containing the secret token.
        """

        return secrets.token_bytes(size)

    @staticmethod
    def deriveKey(salt: bytes, password: str) -> bytes:
        """
        A method to derive a key using password and salt token.

        Parameters
        ----------
        salt : bytes
            The bytes strings containing the salt token.
        password : str
            The strings of characters containing the password.

        Returns
        -------
        bytes
            The method returns bytes string containing the derived key.
        """

        # derive key using salt and password
        key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return key.derive(password.encode())

    @staticmethod
    def readFileAndCreateFernet(
        filename: str,
        key: bytes,
        command: Literal["ENCRYPT", "DECRYPT"] = "ENCRYPT",
    ) -> tuple[Fernet, bytes]:
        """
        A method to read file and create Fernet object.

        Parameters
        ----------
        filename : str
            The strings of characters containing file name.
        key : bytes
            A bytes of stings containing the encryption key.

        Returns
        -------
        Fernet, bytes
            The method returns a Fernet object and the file data as bytes.
        """

        fernet = Fernet(key)

        try:
            with Path(filename).open("rb") as file:
                if command == "DECRYPT":
                    # skip metadata line for decryption
                    file.readline()
                fileData = file.read()

        except FileNotFoundError:
            raise EncryptionException.FileNotFound("File not found")

        return fernet, fileData
