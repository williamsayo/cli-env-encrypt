import os
import base64
import secrets
import sys
from venv import logger

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import cryptography


class EncryptionHelper:
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

    @staticmethod
    def generate_salt(size: int):
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
    def load_salt(filename: str):
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
            # load salt from salt file
            with open(filename.replace(".encrypted", ".salt"), "rb") as salt_file:
                salt = salt_file.read()
            return salt
        except FileNotFoundError:
            raise FileNotFoundError(f"Salt file {filename.replace('.encrypted', '.salt')} not found.")

    @staticmethod
    def derive_key(salt: bytes, password: str):
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
    def generate_key(
        password: str,
        filename: str,
        save_salt=False,
        load_existing_salt=None,
    ) -> bytes:
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
            salt = EncryptionHelper.load_salt(filename)

        if save_salt:
            # generate new salt/token and save it to file
            salt = EncryptionHelper.generate_salt(16)

            with open(f"{filename}.salt", "wb") as salt_file:
                salt_file.write(salt)

        # generate the key from the salt and the password
        derived_key = EncryptionHelper.derive_key(salt, password)

        # encode it using Base 64 and return it
        return base64.urlsafe_b64encode(derived_key)

    @staticmethod
    def readFileAndCreateFernet(
        filename: str,
        key: bytes,
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
            with open(filename, "rb") as file:
                fileData = file.read()

        except FileNotFoundError:
            logger.error("File not found")
            raise FileNotFoundError("File not found")

        return fernet, fileData

    @staticmethod
    def encrypt(filename: str, key: bytes) -> None:
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

        fernet, fileData = EncryptionHelper.readFileAndCreateFernet(filename, key)

        # encrypting file_data
        encryptedData = fernet.encrypt(fileData)

        # writing to a new file with the encrypted data
        with open(f"{filename}.encrypted", "wb") as encryptedFile:
            encryptedFile.write(encryptedData)

        # delete original file after encrypting file
        os.remove(filename)

        logger.info("File encrypted successfully...")
        return 'File encrypted successfully...'

    @staticmethod
    def decrypt(filename: str, key: bytes) -> None:
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

        fernet, encryptedData = EncryptionHelper.readFileAndCreateFernet(filename, key)

        # decrypt data using the Fernet object
        try:
            decryptedData = fernet.decrypt(encryptedData)
        except cryptography.fernet.InvalidToken:
            message = "Invalid token, likely the password is incorrect."
            logger.error(message)
            return message

        # write the original file with decrypted content
        with open(filename.replace(".encrypted", ""), "wb") as file:
            file.write(decryptedData)

        # cleanup: delete the salt file
        saltFileName = filename.replace(".encrypted", ".salt")
        os.remove(saltFileName)

        # delete decrypted file
        os.remove(filename)

        logger.info("File decrypted successfully...")
        return "File decrypted successfully..."
