import os
import unittest
from encryptionHelper import EncryptionHelper

class TestEnvVarsEncryption(unittest.TestCase):
    def setUp(self):
        """Set up test variables."""
        with open(".env", "w") as file:
            file.write("TEST_ENV_VAR=testing123\nANOTHER_ENV_VAR=hello_world")
        self.password = "strongpassword"
        self.filename = ".env"
        self.encryptedFileName = ".env.encrypted"
        self.envEncryption = EncryptionHelper()

    def tearDown(self):
        # delete test salt file from file
        saltFileName = f'{self.filename}.salt'
        if os.path.exists(saltFileName):
            os.remove(saltFileName)

        # delete test encrypted file from file
        encryptedFileName = f"{self.filename}.encrypted"
        if os.path.exists(encryptedFileName):
            os.remove(encryptedFileName)

    @classmethod
    def tearDownClass(cls):
        # delete test salt file from file
        fileName = f'.env'
        if os.path.exists(fileName):
            os.remove(fileName)

    def test_is_instance(self):
        """Test class instance."""
        self.assertTrue(isinstance(self.envEncryption, EncryptionHelper))

    def test_generate_key_method(self):
        """Test generate key is instance method and is callable."""
        self.assertTrue(callable(self.envEncryption.generate_key))

    def test_encrypt_method(self):
        """Test encrypt is instance method."""
        self.assertTrue(callable(self.envEncryption.encrypt))

    def test_decrypt_method(self):
        """Test decrypt is instance method."""
        self.assertTrue(callable(self.envEncryption.decrypt))

    def test_salt_file_not_found(self):
        """Test decrypt file not Found"""
        invalidFileName = ".notExist"
        self.assertRaises(
            FileNotFoundError,
            self.envEncryption.generate_key,
            self.password,
            invalidFileName,
            load_existing_salt=True,
        )

    def test_generate_key(self):
        """Test generate key method."""
        key = self.envEncryption.generate_key(
            self.password, self.filename, save_salt=True
        )
        self.assertEqual(type(key), bytes)

    def test_encrypt(self):
        """Test encrypt method."""
        key = self.envEncryption.generate_key(
            self.password, self.filename, save_salt=True
        )
        encrypted = self.envEncryption.encrypt(self.filename, key)
        self.assertEqual(encrypted, "File encrypted successfully...")

    def test_decrypt_file_with_wrong_password(self):
        """Test decrypt file with wrong password"""
        key = self.envEncryption.generate_key(
            self.password, self.filename, save_salt=True
        )
        encrypted = self.envEncryption.encrypt(self.filename, key)
        self.assertEqual(encrypted, "File encrypted successfully...")

        wrong_key = self.envEncryption.generate_key(
            "wrongpassword", self.encryptedFileName, load_existing_salt=True
        )
        decrypted = self.envEncryption.decrypt(
            self.encryptedFileName,
            wrong_key,
        )

        self.assertEqual(decrypted,'Invalid token, likely the password is incorrect.')

    def test_decrypt(self):
        """Test decrypt method."""
        key = self.envEncryption.generate_key(
            self.password, self.filename, save_salt=True
        )
        self.envEncryption.encrypt(self.filename, key)
        decrypted = self.envEncryption.decrypt(self.encryptedFileName, key)
        self.assertEqual(decrypted, "File decrypted successfully...")

if __name__ == "__main__":
    unittest.main()
