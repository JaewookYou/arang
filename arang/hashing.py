# -*- coding: utf-8 -*-
"""
Hash utilities for web hacking.

Provides common hash functions (MD5, SHA1, SHA256)
with support for both str and bytes input.
"""
from __future__ import annotations

import hashlib
from typing import Union


def md5(string: Union[str, bytes], hex_digest: bool = False) -> Union[bytes, str]:
    """
    Calculate MD5 hash of a string or bytes.

    Args:
        string: Input string or bytes to hash
        hex_digest: If True, return hex string instead of bytes

    Returns:
        MD5 hash as bytes (or hex string if hex_digest=True)

    Examples:
        >>> md5('hello').hex()
        '5d41402abc4b2a76b9719d911017c592'
        >>> md5('hello', hex_digest=True)
        '5d41402abc4b2a76b9719d911017c592'
    """
    if isinstance(string, str):
        string = string.encode()
    result = hashlib.md5(string)
    return result.hexdigest() if hex_digest else result.digest()


def sha1(string: Union[str, bytes], hex_digest: bool = False) -> Union[bytes, str]:
    """
    Calculate SHA1 hash of a string or bytes.

    Args:
        string: Input string or bytes to hash
        hex_digest: If True, return hex string instead of bytes

    Returns:
        SHA1 hash as bytes (or hex string if hex_digest=True)

    Examples:
        >>> sha1('hello').hex()
        'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
        >>> sha1('hello', hex_digest=True)
        'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
    """
    if isinstance(string, str):
        string = string.encode()
    result = hashlib.sha1(string)
    return result.hexdigest() if hex_digest else result.digest()


def sha256(string: Union[str, bytes], hex_digest: bool = False) -> Union[bytes, str]:
    """
    Calculate SHA256 hash of a string or bytes.

    Args:
        string: Input string or bytes to hash
        hex_digest: If True, return hex string instead of bytes

    Returns:
        SHA256 hash as bytes (or hex string if hex_digest=True)

    Examples:
        >>> sha256('hello').hex()
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
        >>> sha256('hello', hex_digest=True)
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    """
    if isinstance(string, str):
        string = string.encode()
    result = hashlib.sha256(string)
    return result.hexdigest() if hex_digest else result.digest()


def sha512(string: Union[str, bytes], hex_digest: bool = False) -> Union[bytes, str]:
    """
    Calculate SHA512 hash of a string or bytes.

    Args:
        string: Input string or bytes to hash
        hex_digest: If True, return hex string instead of bytes

    Returns:
        SHA512 hash as bytes (or hex string if hex_digest=True)
    """
    if isinstance(string, str):
        string = string.encode()
    result = hashlib.sha512(string)
    return result.hexdigest() if hex_digest else result.digest()
