# -*- coding: utf-8 -*-
"""
Encoding/Decoding utilities for web hacking.

Provides URL, Base64, and Hex encoding/decoding functions
with support for both str and bytes input.
"""
from __future__ import annotations

import urllib.parse
import base64
import binascii
from typing import Union


def ue(string: Union[str, bytes], enc: str = 'utf-8') -> str:
    """Shorthand for urlencode."""
    return urlencode(string, enc=enc)


def ud(string: Union[str, bytes], enc: str = 'utf-8') -> str:
    """Shorthand for urldecode."""
    return urldecode(string, enc=enc)


def be(string: Union[str, bytes]) -> Union[str, bytes]:
    """Shorthand for b64encode."""
    return b64encode(string)


def bd(string: Union[str, bytes]) -> Union[str, bytes]:
    """Shorthand for b64decode."""
    return b64decode(string)


def he(string: Union[str, bytes]) -> Union[str, bytes]:
    """Shorthand for hexencode."""
    return hexencode(string)


def hd(string: Union[str, bytes]) -> Union[str, bytes]:
    """Shorthand for hexdecode."""
    return hexdecode(string)


def urlencode(string: Union[str, bytes], enc: str = 'utf-8') -> str:
    """
    URL encode a string or bytes.

    Args:
        string: Input string or bytes to encode
        enc: Character encoding to use (default: utf-8)

    Returns:
        URL encoded string

    Examples:
        >>> urlencode('hello world')
        'hello%20world'
        >>> urlencode(b'test', enc='utf-8')
        'test'
    """
    if isinstance(string, bytes):
        return urllib.parse.quote(string.decode(enc), encoding=enc)
    elif isinstance(string, str):
        return urllib.parse.quote(string, encoding=enc)
    else:
        raise TypeError(f'[x] unexpected type: {type(string).__name__}, expected str or bytes')


def urldecode(string: Union[str, bytes], enc: str = 'utf-8') -> str:
    """
    URL decode a string or bytes.

    Args:
        string: Input URL-encoded string or bytes to decode
        enc: Character encoding to use (default: utf-8)

    Returns:
        URL decoded string

    Examples:
        >>> urldecode('hello%20world')
        'hello world'
    """
    if isinstance(string, bytes):
        try:
            return urllib.parse.unquote(string.decode('latin-1'), encoding=enc)
        except Exception:
            return urllib.parse.unquote(string, encoding=enc)
    elif isinstance(string, str):
        return urllib.parse.unquote(string, encoding=enc)
    else:
        raise TypeError(f'[x] unexpected type: {type(string).__name__}, expected str or bytes')


def b64encode(string: Union[str, bytes]) -> Union[str, bytes]:
    """
    Base64 encode a string or bytes.

    Args:
        string: Input string or bytes to encode

    Returns:
        Base64 encoded result (str if input was str, bytes if input was bytes)

    Examples:
        >>> b64encode('hello')
        'aGVsbG8='
        >>> b64encode(b'hello')
        b'aGVsbG8='
    """
    if isinstance(string, bytes):
        return base64.b64encode(string)
    elif isinstance(string, str):
        return base64.b64encode(string.encode('latin-1')).decode('latin-1')
    else:
        raise TypeError(f'[x] unexpected type: {type(string).__name__}, expected str or bytes')


def b64decode(string: Union[str, bytes]) -> Union[str, bytes]:
    """
    Base64 decode a string or bytes.

    Args:
        string: Input Base64-encoded string or bytes to decode

    Returns:
        Base64 decoded result (str if input was str, bytes if input was bytes)

    Examples:
        >>> b64decode('aGVsbG8=')
        'hello'
        >>> b64decode(b'aGVsbG8=')
        b'hello'
    """
    if isinstance(string, bytes):
        return base64.b64decode(string)
    elif isinstance(string, str):
        return base64.b64decode(string.encode('latin-1')).decode('latin-1')
    else:
        raise TypeError(f'[x] unexpected type: {type(string).__name__}, expected str or bytes')


def hexencode(string: Union[str, bytes]) -> Union[str, bytes]:
    """
    Hex encode a string or bytes.

    Args:
        string: Input string or bytes to encode

    Returns:
        Hex encoded result (str if input was str, bytes if input was bytes)

    Examples:
        >>> hexencode('AB')
        '4142'
        >>> hexencode(b'AB')
        b'4142'
    """
    if isinstance(string, bytes):
        return binascii.hexlify(string)
    elif isinstance(string, str):
        return binascii.hexlify(string.encode('latin-1')).decode('latin-1')
    else:
        raise TypeError(f'[x] unexpected type: {type(string).__name__}, expected str or bytes')


def hexdecode(string: Union[str, bytes]) -> Union[str, bytes]:
    """
    Hex decode a string or bytes.

    Args:
        string: Input hex-encoded string or bytes to decode

    Returns:
        Hex decoded result (str if input was str, bytes if input was bytes)

    Examples:
        >>> hexdecode('4142')
        'AB'
        >>> hexdecode(b'4142')
        b'AB'
    """
    if isinstance(string, bytes):
        return binascii.unhexlify(string)
    elif isinstance(string, str):
        try:
            return binascii.unhexlify(string.encode('latin-1')).decode('latin-1')
        except Exception:
            return binascii.unhexlify(string)
    else:
        raise TypeError(f'[x] unexpected type: {type(string).__name__}, expected str or bytes')
