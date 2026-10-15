"""Authenticated encryption at rest using Fernet (AES-128-CBC + HMAC-SHA256).

Supports seamless key rotation via MultiFernet.
"""

from typing import List, Optional
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from app.config import get_settings


class EncryptionError(Exception):
    """Raised when encryption or decryption fails."""
    pass


class TokenEncryptor:
    """Handles authenticated symmetric encryption for OAuth access and refresh tokens.

    Uses Fernet under the hood (AES-128-CBC with PKCS7 padding and HMAC-SHA256).
    MultiFernet is used to support zero-downtime key rotation:
    - Encryption always uses the primary (first) key.
    - Decryption tries all configured keys in order.
    """

    def __init__(self, primary_key: str, rotation_keys: Optional[List[str]] = None):
        """Initialize TokenEncryptor with primary and optional rotation keys.

        Args:
            primary_key: Base64-encoded 32-byte Fernet key.
            rotation_keys: Optional list of older Fernet keys for decryption.
        """
        all_keys = [primary_key] + (rotation_keys or [])
        try:
            fernets = [Fernet(k.strip().encode("utf-8")) for k in all_keys if k and k.strip()]
            if not fernets:
                raise ValueError("At least one valid Fernet key is required.")
            self._crypto = MultiFernet(fernets)
        except Exception as exc:
            raise EncryptionError(f"Failed to initialize encryption cipher: {exc}") from exc

    def encrypt(self, plain_text: Optional[str]) -> Optional[str]:
        """Encrypts a plaintext string to an authenticated ciphertext string.

        Args:
            plain_text: Secret value to encrypt.

        Returns:
            Encrypted ciphertext as a UTF-8 string, or None if plain_text is None.
        """
        if plain_text is None:
            return None
        try:
            encrypted_bytes = self._crypto.encrypt(plain_text.encode("utf-8"))
            return encrypted_bytes.decode("utf-8")
        except Exception as exc:
            raise EncryptionError("Token encryption failed.") from exc

    def decrypt(self, cipher_text: Optional[str]) -> Optional[str]:
        """Decrypts an authenticated ciphertext string back to plaintext.

        Args:
            cipher_text: Encrypted Fernet token.

        Returns:
            Decrypted plaintext string, or None if cipher_text is None.
        """
        if cipher_text is None:
            return None
        try:
            decrypted_bytes = self._crypto.decrypt(cipher_text.encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except InvalidToken as exc:
            raise EncryptionError("Decryption failed: Token is invalid, corrupted, or key is wrong.") from exc
        except Exception as exc:
            raise EncryptionError(f"Decryption error: {exc}") from exc

    def rotate_ciphertext(self, cipher_text: Optional[str]) -> Optional[str]:
        """Re-encrypts ciphertext with the newest primary key if encrypted with an older key.

        Args:
            cipher_text: Existing ciphertext string.

        Returns:
            Re-encrypted ciphertext using the primary key.
        """
        if cipher_text is None:
            return None
        try:
            rotated_bytes = self._crypto.rotate(cipher_text.encode("utf-8"))
            return rotated_bytes.decode("utf-8")
        except Exception as exc:
            raise EncryptionError("Ciphertext rotation failed.") from exc


def get_token_encryptor() -> TokenEncryptor:
    """Factory dependency to build a TokenEncryptor from application settings."""
    settings = get_settings()
    primary = settings.ENCRYPTION_KEY.get_secret_value()
    rotation_keys = []
    if settings.ROTATION_ENCRYPTION_KEYS:
        rotation_keys = [k.strip() for k in settings.ROTATION_ENCRYPTION_KEYS.split(",") if k.strip()]
    return TokenEncryptor(primary_key=primary, rotation_keys=rotation_keys)
