# -*- coding: utf-8 -*-
"""
AES encryption/decryption utilities.

Provides simple interface for AES encryption with helpful error messages.

Example:
    >>> from arang.crypto import aes
    >>> key = b'0123456789abcdef'  # 16 bytes
    >>> iv = b'abcdef0123456789'   # 16 bytes
    >>> encrypted = aes.enc(key, iv, b'Hello, World!')
    >>> decrypted = aes.dec(key, iv, encrypted)
"""
from __future__ import annotations

from typing import Union, Optional, Literal

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


# Usage hint shown on errors
USAGE_HINT = """
Usage: aes.enc(key, iv, data, mode='CBC', padding=True)
       aes.dec(key, iv, data, mode='CBC', padding=True)

Parameters:
  - key: 16/24/32 bytes (AES-128/192/256)
  - iv: 16 bytes (required for CBC, CFB, OFB, CTR modes)
  - data: bytes to encrypt/decrypt
  - mode: 'CBC', 'ECB', 'CFB', 'OFB', 'CTR' (default: 'CBC')
  - padding: True/False - use PKCS7 padding (default: True)

Examples:
  >>> key = b'0123456789abcdef'
  >>> iv = b'abcdef0123456789'
  >>> enc_data = aes.enc(key, iv, b'secret message')
  >>> dec_data = aes.dec(key, iv, enc_data)
"""

# Mode mapping
MODES = {
    'CBC': 'MODE_CBC',
    'ECB': 'MODE_ECB',
    'CFB': 'MODE_CFB',
    'OFB': 'MODE_OFB',
    'CTR': 'MODE_CTR',
}


class AESError(Exception):
    """Custom exception for AES operations with usage hint."""
    
    def __init__(self, message: str, show_hint: bool = True):
        if show_hint:
            message = f"{message}\n{USAGE_HINT}"
        super().__init__(message)


def _check_crypto_available():
    """Check if pycryptodome is installed."""
    if not _CRYPTO_AVAILABLE:
        raise AESError(
            "[x] pycryptodome is not installed.\n"
            "Install it with: pip install pycryptodome",
            show_hint=False
        )


def _validate_key(key: bytes) -> None:
    """Validate AES key length."""
    if not isinstance(key, bytes):
        raise AESError(f"[x] key must be bytes, got {type(key).__name__}")
    if len(key) not in (16, 24, 32):
        raise AESError(f"[x] key must be 16, 24, or 32 bytes, got {len(key)} bytes")


def _validate_iv(iv: Optional[bytes], mode: str) -> None:
    """Validate IV for modes that require it."""
    if mode == 'ECB':
        return  # ECB doesn't use IV
    if iv is None:
        raise AESError(f"[x] iv is required for {mode} mode")
    if not isinstance(iv, bytes):
        raise AESError(f"[x] iv must be bytes, got {type(iv).__name__}")
    if len(iv) != 16:
        raise AESError(f"[x] iv must be 16 bytes, got {len(iv)} bytes")


def _validate_data(data: Union[str, bytes], operation: str) -> bytes:
    """Validate and convert input data to bytes."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if not isinstance(data, bytes):
        raise AESError(f"[x] data must be str or bytes for {operation}, got {type(data).__name__}")
    return data


def _get_mode(mode_name: str):
    """Get AES mode constant from pycryptodome."""
    mode_name = mode_name.upper()
    if mode_name not in MODES:
        raise AESError(f"[x] unsupported mode: {mode_name}. Supported: {', '.join(MODES.keys())}")
    return getattr(AES, MODES[mode_name])


def enc(
    key: bytes,
    iv: Optional[bytes],
    data: Union[str, bytes],
    mode: str = 'CBC',
    padding: bool = True
) -> bytes:
    """
    Encrypt data using AES.

    Args:
        key: Encryption key (16/24/32 bytes for AES-128/192/256)
        iv: Initialization vector (16 bytes, not needed for ECB)
        data: Data to encrypt (str or bytes)
        mode: AES mode - 'CBC', 'ECB', 'CFB', 'OFB', 'CTR' (default: 'CBC')
        padding: Use PKCS7 padding (default: True)

    Returns:
        Encrypted data as bytes

    Raises:
        AESError: On invalid parameters with usage hint

    Example:
        >>> key = b'0123456789abcdef'
        >>> iv = b'abcdef0123456789'
        >>> encrypted = aes.enc(key, iv, b'Hello!')
    """
    _check_crypto_available()
    _validate_key(key)
    _validate_iv(iv, mode.upper())
    data = _validate_data(data, 'encryption')
    
    aes_mode = _get_mode(mode)
    
    try:
        if mode.upper() == 'ECB':
            cipher = AES.new(key, aes_mode)
        elif mode.upper() == 'CTR':
            cipher = AES.new(key, aes_mode, nonce=iv[:8])
        else:
            cipher = AES.new(key, aes_mode, iv)
        
        if padding and mode.upper() not in ('CTR', 'CFB', 'OFB'):
            data = pad(data, AES.block_size)
        
        return cipher.encrypt(data)
    except Exception as e:
        raise AESError(f"[x] encryption failed: {e}")


def dec(
    key: bytes,
    iv: Optional[bytes],
    data: bytes,
    mode: str = 'CBC',
    padding: bool = True
) -> bytes:
    """
    Decrypt data using AES.

    Args:
        key: Decryption key (16/24/32 bytes for AES-128/192/256)
        iv: Initialization vector (16 bytes, not needed for ECB)
        data: Data to decrypt (bytes)
        mode: AES mode - 'CBC', 'ECB', 'CFB', 'OFB', 'CTR' (default: 'CBC')
        padding: Remove PKCS7 padding (default: True)

    Returns:
        Decrypted data as bytes

    Raises:
        AESError: On invalid parameters with usage hint

    Example:
        >>> key = b'0123456789abcdef'
        >>> iv = b'abcdef0123456789'
        >>> decrypted = aes.dec(key, iv, encrypted_data)
    """
    _check_crypto_available()
    _validate_key(key)
    _validate_iv(iv, mode.upper())
    
    if not isinstance(data, bytes):
        raise AESError(f"[x] encrypted data must be bytes, got {type(data).__name__}")
    
    aes_mode = _get_mode(mode)
    
    try:
        if mode.upper() == 'ECB':
            cipher = AES.new(key, aes_mode)
        elif mode.upper() == 'CTR':
            cipher = AES.new(key, aes_mode, nonce=iv[:8])
        else:
            cipher = AES.new(key, aes_mode, iv)
        
        decrypted = cipher.decrypt(data)
        
        if padding and mode.upper() not in ('CTR', 'CFB', 'OFB'):
            decrypted = unpad(decrypted, AES.block_size)
        
        return decrypted
    except Exception as e:
        raise AESError(f"[x] decryption failed: {e}")


# Convenience aliases
encrypt = enc
decrypt = dec
