# -*- coding: utf-8 -*-
"""
Packet parsing utilities for HTTP request manipulation.

Provides parsePacket class for parsing raw HTTP packets from
Fiddler or Burp Suite and sending requests using the requests library.
"""
from __future__ import annotations

import re
from typing import Optional, Dict, Any

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class parsePacket:
    """
    Parse raw HTTP packets from Fiddler or Burp Suite.

    Attributes:
        url: The parsed URL from the packet
        method: HTTP method (GET, POST, etc.)
        headers: Dictionary of HTTP headers
        data: Request body data
        proxies: Proxy configuration
        s: requests.Session instance
        redirect: Whether to follow redirects
        silent: Whether to suppress output
        timeout: Request timeout in seconds

    Example:
        >>> raw = '''GET http://example.com/ HTTP/1.1
        ... Host: example.com
        ... User-Agent: Mozilla/5.0
        ... '''
        >>> pp = parsePacket(raw)
        >>> r = pp.get(pp.url, headers=pp.headers)
    """

    def __init__(self, packet: str):
        """
        Initialize parsePacket with a raw HTTP packet.

        Args:
            packet: Raw HTTP packet string from Fiddler or Burp Suite
        """
        self.url: str = ''
        self.method: str = ''
        self.headers: Dict[str, str] = {}
        self.data: str = ''
        self.proxies: Dict[str, str] = {}
        self.s: requests.Session = requests.session()
        self.redirect: bool = True
        self.silent: bool = False
        self.timeout: int = 30

        self._parse_packet(packet)

    def _parse_packet(self, packet: str) -> None:
        """Parse the raw packet into components."""
        lines = packet.split('\n')

        # Parse method
        self.method = lines[0].split(' ')[0]

        # Parse URL
        # Fiddler includes scheme/host at first line
        if lines[0].split(' ')[1][:4] == 'http':
            self.url = lines[0].split(' ')[1]
        # Burp doesn't include that, so parse host header to make URL
        else:
            self.url = 'http://' + self._parse_burp_url(packet) + lines[0].split(' ')[1]

        # Parse headers
        if '\n\n' in packet:
            head_lines = packet.split('\n\n')[0].split('\n')[1:]
            self.data = '\n\n'.join(packet.split('\n\n')[1:])
        else:
            head_lines = [x for x in packet.split('\n')[1:] if x and x.strip()]

        for line in head_lines:
            if ':' in line:
                key = line.split(':')[0].strip()
                data = ':'.join(line.split(':')[1:]).strip()
                self.headers[key] = data

    # Backward compatibility alias
    def parsePacket(self, packet: str) -> None:
        """Backward compatibility alias for _parse_packet."""
        self._parse_packet(packet)

    def sequentialIntruder(
        self,
        packet: str,
        to: Optional[int] = None,
        option: str = 'upper',
        find: Optional[str] = None,
        hexed: bool = False,
        verbose: bool = True,
        showContent: bool = False,
        resultSaveWithFile: Optional[str] = None,
        thread: int = 0
    ) -> Dict[int, requests.Response]:
        """
        Sequential intruder like Burp Suite's function.

        Uses $@#<number>#@$ pattern in packet to iterate through values.

        Args:
            packet: Raw packet with $@#<number>#@$ pattern
            to: End value for iteration
            option: 'upper' to count up, 'lower' to count down
            find: String to search for in responses
            hexed: Treat numbers as hexadecimal
            verbose: Print progress information
            showContent: Print response content
            resultSaveWithFile: Filename to save results
            thread: Number of threads (not yet implemented)

        Returns:
            Dictionary mapping iteration numbers to Response objects

        Example:
            >>> raw = 'GET http://example.com/?id=$@#1#@$ HTTP/1.1\\nHost: example.com'
            >>> pp = parsePacket(raw)
            >>> results = pp.sequentialIntruder(raw, to=10, option='upper')
        """
        if '$@#' not in packet or '#@$' not in packet:
            print('[x] intruder params is not set')
            print('    Usage: Include $@#<number>#@$ pattern in packet')
            return {}

        if to is None:
            print('[x] please set `to` param for setting limit of intruder number')
            print('    Usage: sequentialIntruder(packet, to=100)')
            return {}

        origin_num = packet.split('$@#')[1].split('#@$')[0]

        if not self.silent:
            if hexed:
                print(f'[+] doing sequential intruder from {hex(int(origin_num, 16))} to {hex(to)}')
            else:
                print(f'[+] doing sequential intruder from {origin_num} to {to}')

        try:
            if hexed:
                hex_prefix = origin_num[:2] == '0x'
                origin_num = int(origin_num, 16)
            else:
                origin_num = int(origin_num)
        except ValueError:
            print('[x] please set `int type` parameter to use sequential intruder')
            return {}
        except Exception as e:
            print(f'[x] unexpected error: {e}')
            return {}

        result: Dict[int, requests.Response] = {}
        cnt = 0

        if resultSaveWithFile:
            with open(resultSaveWithFile, 'wb') as f:
                f.write(b'')

        step = 1 if option.lower() == 'upper' else -1
        end = to + 1 if option.lower() == 'upper' else to - 1

        for intrude_num in range(origin_num, end, step):
            if hexed:
                if hex_prefix:
                    t_packet = re.sub(r'\$@#.+#@\$', hex(intrude_num), packet)
                else:
                    t_packet = re.sub(r'\$@#.+#@\$', hex(intrude_num)[2:], packet)
            else:
                t_packet = re.sub(r'\$@#.+#@\$', str(intrude_num), packet)

            self._parse_packet(t_packet)

            result_save_content = f'\n[+] doing - {cnt}\n'
            result_save_content += f'url - {self.url}\n'
            result_save_content += f'intrude number - {intrude_num}'

            if verbose:
                print(result_save_content)
            if resultSaveWithFile:
                with open(resultSaveWithFile, 'ab') as f:
                    f.write(result_save_content.encode())

            if self.method.upper() == 'GET':
                r = self.get(self.url, headers=self.headers, proxies=self.proxies)
            elif self.method.upper() == 'POST':
                r = self.post(self.url, headers=self.headers, data=self.data, proxies=self.proxies)
            else:
                print('[x] please use `GET` or `POST` method')
                return result

            if r is None:
                cnt += 1
                continue

            if showContent:
                content = r.content.decode() if isinstance(r.content, bytes) else str(r.content)
                print(f'[+] response packet{content}\n\n')

            if resultSaveWithFile:
                with open(resultSaveWithFile, 'ab') as f:
                    content = r.content if isinstance(r.content, bytes) else str(r.content).encode()
                    f.write(b'[+] response packet' + content + b'\n\n')

            cnt += 1
            if find:
                find_bytes = find.encode() if isinstance(find, str) else find
                if find_bytes in r.content:
                    print(f'[!] {intrude_num} find value - {find}')
                    for x in r.content.split(b'\n'):
                        if find_bytes in x:
                            print(f'--> {x}')
                    print('-------------------------')

            result[intrude_num] = r

        return result

    def _parse_burp_url(self, packet: str) -> str:
        """Extract host from Burp-style packet."""
        for line in packet.split('\n'):
            parts = line.split(' ')
            if parts[0] == 'Host:':
                return parts[1].strip()
        return ''

    # Backward compatibility alias
    def parseBurpUrl(self, packet: str) -> str:
        """Backward compatibility alias for _parse_burp_url."""
        return self._parse_burp_url(packet)

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        proxies: Optional[Dict[str, str]] = None
    ) -> Optional[requests.Response]:
        """
        Send GET request.

        Args:
            url: Target URL
            headers: Optional headers dictionary
            proxies: Optional proxies dictionary

        Returns:
            Response object or None on error
        """
        if not self.silent:
            print(f'[+] get to {url}')
        try:
            r = self.s.get(
                url,
                headers=headers,
                proxies=self.proxies,
                allow_redirects=self.redirect,
                verify=False,
                timeout=self.timeout
            )
            return r
        except Exception as e:
            print(f'[x] connection err: {e}')
            return None

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: str = '',
        proxies: Optional[Dict[str, str]] = None
    ) -> Optional[requests.Response]:
        """
        Send POST request.

        Args:
            url: Target URL
            headers: Optional headers dictionary
            data: Request body data
            proxies: Optional proxies dictionary

        Returns:
            Response object or None on error
        """
        if not self.silent:
            print(f'[+] post to {url}')
        try:
            r = self.s.post(
                url,
                data=data,
                headers=headers,
                proxies=self.proxies,
                allow_redirects=self.redirect,
                verify=False,
                timeout=self.timeout
            )
            return r
        except Exception as e:
            print(f'[x] connection err: {e}')
            return None

    def setProxy(self, host: str) -> None:
        """
        Set HTTP/HTTPS proxy.

        Args:
            host: Proxy host in format 'host:port'

        Example:
            >>> pp.setProxy('127.0.0.1:8080')
        """
        self.proxies['http'] = host
        self.proxies['https'] = host
        if not self.silent:
            print(f'[+] set proxy at {host}')
