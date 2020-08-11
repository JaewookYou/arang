#-*- coding: utf-8 -*-
import requests
import sys
import urllib
import time
import re
import json
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

    def parseBurpUrl(self, packet):
        host = ''.join([line.split(' ')[1] if 'Host:'==line.split(' ')[0] else '' for line in packet.split('\n')])
        return host
    
    def get(self, url, headers=None, data='', proxies=None):
        if not self.silent:
            print('[+] get to {}'.format(url))
        return self.s.get(url, headers=headers, proxies=self.proxies, allow_redirects=self.redirect, verify=False)
    
    def post(self, url, headers=None, data='', proxies=None):
        if not self.silent:
            print('[+] post to {}'.format(url))
        return self.s.post(url, data=data, headers=headers, proxies=self.proxies, allow_redirects=self.redirect, verify=False)
    
    def setProxy(self, host):
        self.proxies['http'] = host
        self.proxies['https'] = host
        if not self.silent:
            print('[+] set proxy at {}'.format(host))

"""
example code
-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
from arang import *

rawPacket='''GET http://ar9ang3.com/ HTTP/1.1
Host: ar9ang3.com
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


'''

pp = parsePacket(rawPacket)
print('-------parsed packet--------')
print('pp.method - {}'.format(pp.method))
print('pp.url - {}'.format(pp.url))
print('pp.headers - {}'.format(pp.headers))
print('pp.data - {}'.format(pp.data))
print('----------------------------')
pp.redirect = False
pp.setProxy('192.168.20.80:8888')

r = pp.post(pp.url,headers=pp.headers,data=pp.data)

print(r.content)
-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
"""