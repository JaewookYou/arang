# -*- coding: utf-8 -*-
"""
arang - A Python module for web hacking and security testing.

This module provides utilities for:
- HTTP packet parsing and manipulation (parsePacket)
- Encoding/decoding (URL, Base64, Hex)
- Hashing (MD5, SHA1, SHA256, SHA512)
- Clipboard operations (pp)
- Cryptography (AES, SEED)

Example:
    >>> from arang import *
    >>> 
    >>> # URL encoding
    >>> urlencode('hello world')
    'hello%20world'
    >>> 
    >>> # Clipboard
    >>> pp('text to copy')
    'text to copy'
    >>> 
    >>> # Encryption
    >>> from arang.crypto import aes
    >>> encrypted = aes.enc(key, iv, b'secret')
"""
from __future__ import annotations

__version__ = '2.0.0'
__author__ = 'arang (Jaewook You)'

# Re-export packet parsing
from .packet import parsePacket

# Re-export encoding utilities
from .encoding import (
    urlencode, urldecode, ue, ud,
    b64encode, b64decode, be, bd,
    hexencode, hexdecode, he, hd,
)

# Re-export hashing utilities
from .hashing import md5, sha1, sha256, sha512

# Re-export clipboard utilities
from .clipboard import pp, paste

# For test function (backward compatibility)
def test():
    """Test function for debugging."""
    print('arang module loaded successfully!')
    print(f'Version: {__version__}')

# What gets exported with 'from arang import *'
__all__ = [
    # Version info
    '__version__',
    '__author__',
    
    # Packet parsing
    'parsePacket',
    
    # Encoding (full names)
    'urlencode', 'urldecode',
    'b64encode', 'b64decode',
    'hexencode', 'hexdecode',
    
    # Encoding (short names)
    'ue', 'ud',
    'be', 'bd',
    'he', 'hd',
    
    # Hashing
    'md5', 'sha1', 'sha256', 'sha512',
    
    # Clipboard
    'pp', 'paste',
    
    # Misc
    'test',
]
