#-*- coding: utf-8 -*-
import requests
import sys
import time
import re
import json
import urllib.parse
import base64, binascii
import hashlib
from concurrent.futures import ThreadPoolExecutor
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class parsePacket:
    def __init__(self, packet):
        self.url = ''
        self.method = ''
        self.headers = {}
        self.data = ''
        self.proxies = {}
        self.s = requests.session()
        self.redirect = True
        self.silent = False
        self.timeout = 30

        self.parsePacket(packet)

    def parsePacket(self, packet):
        lines = packet.split('\n')

        ## parse method
        self.method = lines[0].split(' ')[0]

        ## parse url
        # fiddler is including scheme/host at first line
        if lines[0].split(' ')[1][:4] == 'http':
            self.url = lines[0].split(' ')[1]
        # but burp isn't including that, so parse host header to make url
        else:
            self.url = self.parseBurpUrl(packet) + lines[0].split(' ')[1]
        
        ## parse headers
        if '\n\n' in packet:
            headLines = packet.split('\n\n')[0].split('\n')[1:]
            self.data = '\n\n'.join(packet.split('\n\n')[1:])
        else:
            headLines = [x if x != None and x != '' else '!!' for x in packet.split('\n')[1:]]
            headLines.remove('!!')
        for line in headLines:
            key = line.split(':')[0].strip()
            data = line.split(':')[1].strip()
            self.headers[key] = data
        
    
    ## function like burpsuite's intruder
    # default setting value is configured by upper & verbose
    def sequentialIntruder(self, packet, to=None, option='upper', hexed=False, verbose=True, showContent=False, resultSaveWithFile=False):
        if '$@#' not in packet and '#@$' not in packet:
            print('[x] intruder params is not set')
            return
        if to == None:
            print('[x] please set `to` param for setting limit of intruder number')
            return

        originNum = packet.split('$@#')[1].split('#@$')[0]

        if not self.silent:
            if hexed:
                print('[+] doing sequential intruder from {} to {}'.format(hex(int(originNum,16)), hex(to)))
            else:
                print('[+] doing sequential intruder from {} to {}'.format(originNum, to))

        try:
            if hexed:
                if originNum[:2]=='0x':
                    hexPrefix = True
                else:
                    hexPrefix = False
                originNum = int(originNum,16)
            else:
                originNum = int(originNum)
        except ValueError:
            print('[x] please set `int type` parameter to use sequential intruder')
            return
        except:
            print('[x] sorry.. unexpected error')
            return

        result = {}
        cnt = 0

        if resultSaveWithFile:
            with open(resultSaveWithFile, 'wb') as f:
                f.write(b'')

        for intrudeNum in range(originNum, to+1 if option.lower()=='upper' else to-1, 1 if option.lower()=='upper' else -1):
            if self.method.upper() == 'GET':
                if hexed:
                    if hexPrefix:
                        tpacket = re.sub('\$@#.+#@\$', hex(intrudeNum), packet)
                    else:
                        tpacket = re.sub('\$@#.+#@\$', hex(intrudeNum)[2:], packet)
                else:
                    tpacket = re.sub('\$@#.+#@\$', str(intrudeNum), packet)

                self.parsePacket(tpacket)
                
                resultSaveContent = ''
                resultSaveContent += '\n[+] doing - {}\n'.format(cnt)
                resultSaveContent += 'url - {}\n'.format(self.url)
                resultSaveContent += 'intrude number - {}'.format(intrudeNum)
                if verbose:
                    print(resultSaveContent)
                if resultSaveWithFile:
                    with open(resultSaveWithFile, 'ab') as f:
                        f.write(resultSaveContent.encode())
                
                r = self.get(self.url, headers = self.headers, proxies = self.proxies)

                resultSaveContent = ''
                resultSaveContent += '[+] response packet'
                resultSaveContent += r.content.decode()
                resultSaveContent += '\n\n'
                if showContent:
                    print(resultSaveContent)

                if resultSaveWithFile:
                    with open(resultSaveWithFile, 'ab') as f:
                        f.write(resultSaveContent.encode())

                cnt += 1
                result[intrudeNum] = r

            elif self.method.upper() == 'POST':
                if hexed:
                    if hexPrefix:
                        tpacket = re.sub('\$@#.+#@\$', hex(intrudeNum), packet)
                    else:
                        tpacket = re.sub('\$@#.+#@\$', hex(intrudeNum)[2:], packet)
                else:
                    tpacket = re.sub('\$@#.+#@\$', str(intrudeNum), packet)
                self.parsePacket(tpacket)

                resultSaveContent = ''
                resultSaveContent += '\n[+] doing - {}\n'.format(cnt)
                resultSaveContent += 'url - {}\n'.format(self.url)
                resultSaveContent += 'intrude number - {}'.format(intrudeNum)
                if verbose:
                    print(resultSaveContent)
                if resultSaveWithFile:
                    with open(resultSaveWithFile, 'ab') as f:
                        f.write(resultSaveContent.encode())

                r = self.post(self.url, headers = self.headers, data = self.data, proxies = self.proxies)

                resultSaveContent = ''
                resultSaveContent += '[+] response packet'
                resultSaveContent += r.content
                resultSaveContent += '\n\n'
                if showContent:
                    print(resultSaveContent)

                if resultSaveWithFile:
                    with open(resultSaveWithFile, 'ab') as f:
                        f.write(resultSaveContent.encode())

                cnt += 1
                result[intrudeNum] = r
                
            else:
                print('[x] please use `GET` or `POST` method')
                return

        return result


    def parseBurpUrl(self, packet):
        host = ''.join([line.split(' ')[1] if 'Host:'==line.split(' ')[0] else '' for line in packet.split('\n')])
        return host
    
    def get(self, url, headers=None, proxies=None):
        if not self.silent:
            print('[+] get to {}'.format(url))
        try:
            r = self.s.get(url, headers=headers, proxies=self.proxies, allow_redirects=self.redirect, verify=False, timeout=self.timeout)
            return r
        except:
            print('[x] connection err')
            return
    
    def post(self, url, headers=None, data='', proxies=None):
        if not self.silent:
            print('[+] post to {}'.format(url))
        try:
            r = self.s.post(url, data=data, headers=headers, proxies=self.proxies, allow_redirects=self.redirect, verify=False, timeout=self.timeout)
            return r
        except:
            print('[x] connection err')
            return
    
    def setProxy(self, host):
        self.proxies['http'] = host
        self.proxies['https'] = host
        if not self.silent:
            print('[+] set proxy at {}'.format(host))

    

def urlencode(string):
    if type(string)==bytes:
        return urllib.parse.quote(string).encode()
    elif type(string)==str:
        return urllib.parse.quote(string)
    else:
        print('[x] unexpected type')
        return False

def urldecode(string):
    if type(string)==bytes:
        return urllib.parse.unquote(string).encode()
    elif type(string)==str:
        return urllib.parse.unquote(string)
    else:
        print('[x] unexpected type')
        return False

def b64encode(string):
    if type(string)==bytes:
        return base64.b64encode(string)
    elif type(string)==str:
        return base64.b64encode(string.encode()).decode()
    else:
        print('[x] unexpected type')
        return False

def b64decode(string):
    if type(string)==bytes:
        return base64.b64decode(string)
    elif type(string)==str:
        return base64.b64decode(string.encode()).decode()
    else:
        print('[x] unexpected type')
        return False

def hexencode(string):
    if type(string)==bytes:
        return binascii.hexlify(string)
    elif type(string)==str:
        return binascii.hexlify(string.encode()).decode()
    else:
        print('[x] unexpected type')
        return False

def hexdecode(string):
    if type(string)==bytes:
        return binascii.unhexlify(string)
    elif type(string)==str:
        return binascii.unhexlify(string.encode()).decode()
    else:
        print('[x] unexpected type')
        return False

def md5(string):
    if type(string)==bytes:
        return hashlib.md5(string).digest()
    elif type(string)==str:
        return hashlib.md5(string.encode()).digest()

def sha1(string):
    if type(string)==bytes:
        return hashlib.sha1(string).digest()
    elif type(string)==str:
        return hashlib.sha1(string.encode()).digest()

def sha256(string):
    if type(string)==bytes:
        return hashlib.sha256(string).digest()
    elif type(string)==str:
        return hashlib.sha256(string.encode()).digest()
