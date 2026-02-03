from uuid import UUID
import sqlite3
from typing import Tuple
from encryptionHelper import EncryptionException

class DB:
    SCHEMA = """CREATE TABLE IF NOT EXISTS File_Salts (
    file_key TEXT PRIMARY KEY,
    salt BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

    def __init__(self, db_name: str = "salts.db") -> None:
        self._init_db(db_name)

    def _init_db(self, db_path: str) -> None:
        self.connection = sqlite3.connect(db_path)
        self.cursor = self.connection.cursor()

        with self.connection:
            self.cursor.execute(self.SCHEMA)

    def save_salt(self, key: UUID, salt: bytes) -> None:
        try:
            with self.connection:
                self.cursor.execute(
                    "INSERT OR REPLACE INTO File_Salts (file_key, salt) VALUES (:key, :salt);",
                    {"key": str(key), "salt": salt},
                )
        except Exception:
            raise EncryptionException.UnexpectedError()

    def delete_salt(self, key: UUID) -> None:
        with self.connection:
            self.cursor.execute(
                "DELETE FROM File_Salts WHERE file_key = :key;",
                {"key": str(key)},
            )

    def get_salt(self, key: UUID) -> Tuple[bytes, str]:
        with self.connection:
            self.cursor.execute(
                "SELECT salt,created_at FROM File_Salts WHERE file_key = :key;",
                {"key": str(key)},
            )
            result = self.cursor.fetchone()
            if result:
                return result
            else:
                raise KeyError(f"No salt found for key: {key}")

    def close(self) -> None:
        self.connection.close()
