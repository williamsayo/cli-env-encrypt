import uuid
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from encryptionHelper import EncryptionHelper, EncryptionException


class TestEnvVarsEncryption(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        pass

    def setUp(self) -> None:
        """Set up test variables."""
        self.filePath = Path(self.create_temp_file(
            b"TEST_ENV_VAR=testing123\nANOTHER_ENV_VAR=hello_world"
        ))
        self.mock_salt_store = MagicMock()
        self.mock_logger = MagicMock()
        self.password = "strongpassword"
        self.encryptedFileName = self.filePath.with_name(f"{self.filePath.name}.encrypted")
        self.envEncryption = EncryptionHelper(self.mock_salt_store, self.mock_logger)

    def tearDown(self) -> None:
        # delete test encrypted file from file
        if Path.exists(self.filePath):
            Path.unlink(self.filePath)

        if Path.exists(self.encryptedFileName):
            Path.unlink(self.encryptedFileName)

    def create_temp_file(self, content: bytes) -> str:
        temp = tempfile.NamedTemporaryFile(delete=False)
        temp.write(content)
        temp.close()
        return temp.name

    @classmethod
    def tearDownClass(cls) -> None:
        pass

    def test_is_instance(self) -> None:
        """Test class instance."""
        self.assertTrue(isinstance(self.envEncryption, EncryptionHelper))

    def test_generate_key_method(self) -> None:
        """Test generate key is instance method and is callable."""
        self.assertTrue(callable(self.envEncryption.generateKey))

    def test_encrypt_method(self) -> None:
        """Test encrypt is instance method."""
        self.assertTrue(callable(self.envEncryption.encrypt))

    def test_decrypt_method(self) -> None:
        """Test decrypt is instance method."""
        self.assertTrue(callable(self.envEncryption.decrypt))

    def test_file_not_found(self) -> None:
        """Test decrypt/encrypt file not Found"""
        invalidFilePath = Path(".notExist")
        self.assertRaises(
            EncryptionException.FileNotFound,
            self.envEncryption.generateKey,
            self.password,
            invalidFilePath,
            load_existing_salt=True,
        )

    def test_generate_key_return_type(self) -> None:
        """Test generate key method."""
        key, metadata = self.envEncryption.generateKey(
            self.password, self.filePath, save_salt=True
        )
        self.assertIsInstance(key, bytes)
        self.assertIsInstance(metadata, bytes)

    def test_generate_key_creates_new_salt(self) -> None:
        """Test generate key creates new salt."""

        key, _ = self.envEncryption.generateKey(
            self.password,
            self.filePath,
            save_salt=True,
        )

        self.assertIsInstance(key, bytes)
        self.mock_salt_store.save_salt.assert_called_once()

    def test_generate_key_uses_existing_salt(self) -> None:
        existing_salt = (b"existing-salt", "timestamp")
        self.mock_salt_store.get_salt.return_value = existing_salt

        with patch.object(EncryptionHelper, "readMetadata", return_value = uuid.uuid4()):
            key, _ = self.envEncryption.generateKey(
                self.password, self.encryptedFileName, load_existing_salt=True
            )

            self.assertIsInstance(key, bytes)
            self.mock_salt_store.save_salt.assert_not_called()

    def test_encrypt(self) -> None:
        """Test encrypt method."""
        encrypted = self.envEncryption.encrypt(self.password, self.filePath)
        self.assertEqual(encrypted, "File encrypted successfully...")

    def test_decrypt_file_with_wrong_password(self) -> None:
        existing_salt = (b"existing-salt", "timestamp")
        self.mock_salt_store.get_salt.return_value = existing_salt

        """Test decrypt file with wrong password"""
        encrypted = self.envEncryption.encrypt(self.password, self.filePath)
        self.assertEqual(encrypted, "File encrypted successfully...")

        self.assertRaises(
            EncryptionException.IncorrectPassword,
            self.envEncryption.decrypt,
            "wrongpassword",
            self.encryptedFileName,
        )

    def test_decrypt(self) -> None:
        """Test decrypt method."""

        mock_salt = b"existing-salt"
        mock_db_return = (mock_salt, "timestamp")
        self.mock_salt_store.get_salt.return_value = mock_db_return

        with patch.object(EncryptionHelper, "generateSalt", return_value=mock_salt):
            self.envEncryption.encrypt(self.password, self.filePath)

        decrypted = self.envEncryption.decrypt(self.password, self.encryptedFileName)
        self.assertEqual(decrypted, "File decrypted successfully...")


if __name__ == "__main__":
    unittest.main()
