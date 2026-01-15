# -*- coding: utf-8 -*-
"""
Clipboard utilities using pyperclip.

Provides simple clipboard copy function with support for both str and bytes.
"""
from __future__ import annotations

from typing import Union

try:
    import pyperclip
    _PYPERCLIP_AVAILABLE = True
except ImportError:
    _PYPERCLIP_AVAILABLE = False


def pp(text: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    Copy text to clipboard using pyperclip.

    Args:
        text: Text to copy to clipboard (str or bytes)
        encoding: Encoding to use when converting bytes to str (default: utf-8)

    Returns:
        The text that was copied (as str)

    Raises:
        ImportError: If pyperclip is not installed

    Examples:
        >>> pp("Hello, World!")
        'Hello, World!'
        >>> pp(b"Hello bytes")
        'Hello bytes'
        >>> pp(b"\\xed\\x95\\x9c\\xea\\xb8\\x80", encoding='utf-8')  # Korean text
        '한글'
    """
    if not _PYPERCLIP_AVAILABLE:
        raise ImportError(
            "[x] pyperclip is not installed.\n"
            "Install it with: pip install pyperclip\n"
            "Usage: pp(text) - copies text to clipboard"
        )
    
    # Convert bytes to string if needed
    if isinstance(text, bytes):
        try:
            text = text.decode(encoding)
        except UnicodeDecodeError:
            # Fallback: try with errors='replace' to handle binary data
            text = text.decode(encoding, errors='replace')
    elif not isinstance(text, str):
        text = str(text)
    
    pyperclip.copy(text)
    return text


def paste() -> str:
    """
    Get text from clipboard using pyperclip.

    Returns:
        Text currently in clipboard

    Raises:
        ImportError: If pyperclip is not installed
    """
    if not _PYPERCLIP_AVAILABLE:
        raise ImportError(
            "[x] pyperclip is not installed.\n"
            "Install it with: pip install pyperclip"
        )
    
    return pyperclip.paste()
