# arang

Python module for web hacking and security testing.

## Installation

```bash
pip install arang
# or
python -m pip install arang
```

### With SEED crypto support (optional)

```bash
pip install arang[seed]
```

## Update

```bash
pip install -U arang
# or
python -m pip install -U arang
```

## Requirements

- Python 3.8 ~ 3.13
- requests
- pycryptodome
- pyperclip

---

## Features

### parsePacket (class)

Parse raw HTTP packets from Fiddler or Burp Suite and send requests.

```python
from arang import *

rawPacket = '''GET http://example.com/ HTTP/1.1
Host: example.com
Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36

'''

pp = parsePacket(rawPacket)
print('Method:', pp.method)
print('URL:', pp.url)
print('Headers:', pp.headers)
print('Data:', pp.data)

# Configure options
pp.setProxy('127.0.0.1:8080')
pp.redirect = False
pp.silent = True
pp.timeout = 30

# Send request
r = pp.get(pp.url, headers=pp.headers)
print(r.content)
```

---

### Sequential Intruder (like Burp Suite)

Use `$@#<number>#@$` pattern to iterate through values:

```python
from arang import *

rawPacket = '''GET http://example.com/?id=$@#100#@$ HTTP/1.1
Host: example.com

'''

pp = parsePacket(rawPacket)

# Count up from 100 to 272 (hex 0x110)
results = pp.sequentialIntruder(
    rawPacket, 
    to=0x110, 
    option='upper',      # 'upper' or 'lower'
    hexed=True,          # Use hex numbers
    verbose=False,
    showContent=False,
    resultSaveWithFile='result.txt'
)

# Count down from 100 to 90, find specific string
results = pp.sequentialIntruder(
    rawPacket, 
    to=90, 
    option='lower',
    find='target_string',
    verbose=True
)
```

---

### Clipboard (pp function)

Copy text to clipboard. Supports both `str` and `bytes`:

```python
from arang import pp

# Copy string
pp("Hello, World!")

# Copy bytes (auto-converted to string)
pp(b"Hello bytes")

# With custom encoding for Korean text
pp(b"\xed\x95\x9c\xea\xb8\x80", encoding='utf-8')
```

---

### Encoding / Decoding

URL, Base64, and Hex encoding with short aliases:

```python
from arang import *

# URL encoding
urlencode('hello world')       # 'hello%20world'
urldecode('hello%20world')     # 'hello world'
ue('한글', enc='utf-8')        # URL encode Korean
ud('%ED%95%9C%EA%B8%80')       # URL decode

# Base64
b64encode('hello')             # 'aGVsbG8='
b64decode('aGVsbG8=')          # 'hello'
be(b'bytes')                   # Short alias
bd('aGVsbG8=')                 # Short alias

# Hex
hexencode('AB')                # '4142'
hexdecode('4142')              # 'AB'
he(b'data')                    # Short alias
hd('64617461')                 # Short alias
```

---

### Hashing

MD5, SHA1, SHA256, SHA512 with optional hex output:

```python
from arang import *

# Returns bytes by default
md5('hello')                   # b'\x5d\x41...'
sha1('hello')
sha256('hello')
sha512('hello')

# Get hex string
md5('hello', hex_digest=True)  # '5d41402abc4b2a76b9719d911017c592'
sha256(b'bytes', hex_digest=True)
```

---

### Cryptography (AES)

Easy AES encryption/decryption with helpful error messages:

```python
from arang.crypto import aes

key = b'0123456789abcdef'  # 16/24/32 bytes
iv = b'abcdef0123456789'   # 16 bytes

# Encrypt (supports str and bytes)
encrypted = aes.enc(key, iv, b'Hello, World!')
encrypted = aes.enc(key, iv, 'String also works')

# Decrypt
decrypted = aes.dec(key, iv, encrypted)
print(decrypted)  # b'Hello, World!'

# Different modes: CBC (default), ECB, CFB, OFB, CTR
encrypted = aes.enc(key, iv, data, mode='CTR')
encrypted = aes.enc(key, None, data, mode='ECB')  # ECB doesn't need IV

# Without padding
encrypted = aes.enc(key, iv, padded_data, padding=False)
```

**Error messages include usage hints:**
```
[x] key must be 16, 24, or 32 bytes, got 10 bytes

Usage: aes.enc(key, iv, data, mode='CBC', padding=True)
       aes.dec(key, iv, data, mode='CBC', padding=True)

Parameters:
  - key: 16/24/32 bytes (AES-128/192/256)
  - iv: 16 bytes (required for CBC, CFB, OFB, CTR modes)
  - data: bytes
  - mode: 'CBC', 'ECB', 'CFB', 'OFB', 'CTR' (default: 'CBC')
```

---

### Cryptography (SEED)

SEED encryption (Korean standard TTAS.KO-12.0004/R1):

```python
from arang.crypto import seed

key = b'0123456789abcdef'  # 16 bytes only
iv = b'abcdef0123456789'   # 16 bytes

# Encrypt
encrypted = seed.enc(key, iv, b'Hello, World!')

# Decrypt
decrypted = seed.dec(key, iv, encrypted)
print(decrypted)  # b'Hello, World!'

# Without padding
encrypted = seed.enc(key, iv, padded_data, padding=False)
```

> **Note:** Install `kisa-seed` for better performance: `pip install kisa-seed`

---

## Quick Reference

| Function | Short | Description |
|----------|-------|-------------|
| `urlencode(s)` | `ue(s)` | URL encode |
| `urldecode(s)` | `ud(s)` | URL decode |
| `b64encode(s)` | `be(s)` | Base64 encode |
| `b64decode(s)` | `bd(s)` | Base64 decode |
| `hexencode(s)` | `he(s)` | Hex encode |
| `hexdecode(s)` | `hd(s)` | Hex decode |
| `md5(s)` | - | MD5 hash |
| `sha1(s)` | - | SHA1 hash |
| `sha256(s)` | - | SHA256 hash |
| `sha512(s)` | - | SHA512 hash |
| `pp(s)` | - | Copy to clipboard |
| `aes.enc(k, iv, d)` | - | AES encrypt |
| `aes.dec(k, iv, d)` | - | AES decrypt |
| `seed.enc(k, iv, d)` | - | SEED encrypt |
| `seed.dec(k, iv, d)` | - | SEED decrypt |

---

## To-Do List

- [ ] Support ThreadPoolExecutor in intruder for faster exploitation
- [ ] OOB helper with simple webserver (idea from [Zach Wade](https://twitter.com/zwad3))
- [ ] Request smuggling helper
- [ ] Automated blind SQL injection

---

## What's New?

### v2.0.0 (2025-01-16)
- Complete code refactoring into modular structure
- Python 3.8 ~ 3.13 support
- Added `pp()` clipboard function with bytes/str support
- Added `aes` crypto module with multiple modes and helpful errors
- Added `seed` crypto module (Korean standard) with pure Python fallback
- Added `sha512` hash function
- Added `hex_digest` option to hash functions
- Improved type hints and docstrings
- Cleaned up dependencies

### v1.0 (2021-10-15)
- Fix string encoding issue with url, base64, hex encode/decode functions
- Add short version of encode/decode functions
- Support user defined encoding with urlencode/urldecode functions

---

## License

Copyright (C) Jaewook You (arang) (jaewook376 at naver dot com)

License: GNU General Public License, version 2
