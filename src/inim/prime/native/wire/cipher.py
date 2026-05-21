"""
inim.crypto
~~~~~~~~~~~
AES-128-CBC encryption and decryption for the Inim Prime binary wire.

This module derives a key and IV from a shared password and uses them
to encrypt outgoing payloads and decrypt incoming ones.

Responsibilities
----------------
- Deriving the AES-128-CBC key and IV from a password
- Encrypting plaintext payloads before they are embedded in wire frames
- Decrypting ciphertext payloads received from the panel

Key and IV derivation
---------------------
    key[i] = password[i] for i in 0..len(password), zero-padded to 16 bytes
    iv[i]  = i XOR key[i] for i in 0..15

WARNING: The IV is deterministically derived from the key, meaning identical
plaintexts always produce identical ciphertexts. This is by design,
the panel uses the same derivation and would reject frames encrypted
with a different IV.

Dependencies
------------
    pycryptodome — pip install pycryptodome
"""

from __future__ import annotations

from typing import ClassVar

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class Cipher:
    """
    Stateless AES-128-CBC cipher wrapper.

    Holds a derived key and IV pair for the lifetime of the instance.
    Both encrypt() and decrypt() create a fresh cipher object per call
    to ensure the CBC chaining state is always reset to the IV.
    """

    ### Constants
    AES_KEY_SIZE: ClassVar[int] = 16  # AES-128 key size in bytes
    AES_BLOCK_SIZE: ClassVar[int] = 16  # AES block size in bytes


    ### Attributes
    __slots__ = (
        "_key",
        "_iv",
    )


    ### Constructors
    def __init__(
            self,
            password: str,
    ) -> None:
        """
        Derives the AES-128-CBC key and IV from the provided password, saving them as attributes.
        :param password:    UTF-8 password string, 1–16 characters.
        :raises ValueError: If password is empty or longer than 16 characters.
        """

        # Raise an Exception in case the password is empty
        if not password:
            raise ValueError("Password must not be empty.")

        # Raise an Exception in case the password is longer than 16 characters
        if len(password) > self.AES_KEY_SIZE:
            raise ValueError(f"Password must be at most {self.AES_KEY_SIZE} characters, got {len(password)}.")

        # Encodes the password in utf-8 and creates the key, by inserting each char in 16-bytes array.
        # In case the password is shorter than 16 characters, the key is padded with 0 at the end.
        password_bytes = password.encode("utf-8")
        key = bytearray(self.AES_KEY_SIZE)
        key[:len(password_bytes)] = password_bytes[:self.AES_KEY_SIZE]

        # Derives a static IV by XORing each key byte with its index position.
        # WARNING: fixed IV means identical plaintexts produce identical ciphertexts.
        # Do not randomise the IV as the panel derives it the same way and would reject frames encrypted with a different IV.
        iv = bytearray(self.AES_KEY_SIZE)
        for idx in range(self.AES_KEY_SIZE):
            iv[idx] = idx ^ key[idx]

        # Store as immutable bytes to prevent accidental modification after construction
        self._key: bytes = bytes(key)
        self._iv: bytes = bytes(iv)


    ### Main
    def encrypt(
            self,
            plaintext: bytes,
    ) -> bytes:
        """
        Encrypts plaintext bytes using AES-128-CBC.
        :param plaintext:   Plaintext bytes to encrypt.
                            Any length is accepted, padding is applied automatically.
        :return:            AES-128-CBC ciphertext. Always a multiple of 16 bytes.
        """

        # A new cipher object must be created for each call.
        # Reusing would corrupt the CBC chaining state.
        cipher = AES.new(self._key, AES.MODE_CBC, self._iv)

        # Pad plaintext to a multiple of 16 bytes using PKCS#7, then encrypt and return the ciphertext.
        return cipher.encrypt(pad(plaintext, self.AES_BLOCK_SIZE))

    def decrypt(
            self,
            cipher_text: bytes,
    ) -> bytes:
        """
        Decrypts AES-128-CBC ciphertext and removes padding.
        :param cipher_text:     AES-128-CBC ciphertext to decrypt. Must be a multiple of 16 bytes.
        :return:                Decrypted plaintext bytes with padding removed.
        :raises ValueError:     If the ciphertext length is not a multiple of 16 bytes or if the padding is invalid after decryption.
        """

        # A new cipher object must be created for each call.
        # Reusing would corrupt the CBC chaining state.
        cipher = AES.new(self._key, AES.MODE_CBC, self._iv)

        # Decrypt the ciphertext and remove PKCS#7 padding.
        # Raises ValueError if ciphertext length is invalid or padding is malformed.
        # This indicates either a wrong key/IV or a corrupted frame.
        return unpad(cipher.decrypt(cipher_text), self.AES_BLOCK_SIZE)
