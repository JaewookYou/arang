from arang import *

rawPacket='''GET http://ar9ang3.com/?$@#100#@$ HTTP/1.1
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

pp.setProxy('192.168.20.80:8888')
pp.redirect = False
pp.silent = False
pp.timeout = 30

r = pp.post(pp.url,headers=pp.headers,data=pp.data)
print(r.content)

## sequential intruder like burp's function
# --- function's definition
# def sequentialIntruder(self, packet, to=None, option='upper', hexed=False, verbose=True, showContent=False, resultSaveWithFile=False):
# --- 
print('\n\n[+] upper intruder test - hexed=True, verbose=False, showContent=False, resultSaveWithFile="result.txt"')
rr = pp.sequentialIntruder(rawPacket, to=0x110, option='upper', hexed=True, verbose=False, showContent=False, resultSaveWithFile='result.txt')
print(rr)
print('-====================-')
print('[+] lower intruder test - option="lower", verbose=True')
rr = pp.sequentialIntruder(rawPacket, to=90, option='lower', verbose=True)
print(rr)

## misc utils
print('\n\n[+] misc util test.. url,b64,hex,hash\n')
string = 'ABCD!@#$'
print(f'urlencode : {string} - {urlencode(string)}')
print(f'urldecode : {urlencode(string)} - {urldecode(urlencode(string))}')
print(f'b64encode : {string} - {b64encode(string)}')
print(f'b64decode : {b64encode(string)} - {b64decode(b64encode(string))}')
print(f'hexencode : {string} - {hexencode(string)}')
print(f'hexdecode : {hexencode(string)} - {hexdecode(hexencode(string))}')
print(f'md5       : {string} - {md5(string)}')
print(f'sha1      : {string} - {sha1(string)}')
print(f'sha256    : {string} - {sha256(string)}')
