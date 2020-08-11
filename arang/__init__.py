#-*- coding: utf-8 -*-
import requests
import sys
import urllib
import time
import re
import json
import arang
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
        #print(re.sub('\d{4}', 'XXXX', '010-1234-5678'))
    
    ## function like burpsuite's intruder
    # default setting value is configured by upper & verbose
    def sequencialIntruder(self, packet, to=None, option='upper', hexed=False, verbose=True, showContent=False, resultSaveWithFile=False):
        if '$@#' not in packet and '#@$' not in packet:
            print('[x] intruder params is not set')
            return
        if to == None:
            print('[x] please set `to` param for setting limit of intruder number')
            return

        originNum = packet.split('$@#')[1].split('#@$')[0]

        if not self.silent:
            if hexed:
                print('[+] doing sequencial intruder from {} to {}'.format(hex(int(originNum,16)), hex(to)))
            else:
                print('[+] doing sequencial intruder from {} to {}'.format(originNum, to))

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
            print('[x] please set `int type` parameter to use sequencial intruder')
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

    
