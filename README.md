# arang
my own module for webhacking using python3


## how to install
 - pip3 install arang
 - python3 -m pip install arang


## how to update
 - pip3 install -U arang
 - python3 -m pip install -U arang


## support functions

### parsePacket (class)
 - parse raw packet from `fiddler` or `burp suite`
 - send GET&POST by using `requests.session()` with `pp.*args`
 - set proxies server
 - set allow_redirects

example code
```python
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

pp.setProxy('192.168.20.80:8888')
pp.redirect = False

r = pp.post(pp.url,headers=pp.headers,data=pp.data)

print(r.content)
```


### sequential intruder (like burp func)
 - parse `\$@#\d+#@\$`(example `$@#100#@$`) form and do intruder from raw packet of fiddler or burpsuite
 - can choose going up or down
 - can choose input as hex/decimal number
 - can save result with specific file
 - return requests result object by dictionary type

```python
rawPacket='''GET http://ar9ang3.com/?$@#100#@$ HTTP/1.1
Host: ar9ang3.com
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


'''

print('[+] upper intruder test - hexed=True, verbose=False, showContent=False, resultSaveWithFile="result.txt"')
rr = pp.sequencialIntruder(rawPacket, to=0x110, option='upper', hexed=True, verbose=False, showContent=False, resultSaveWithFile='result.txt')
print(rr)
'''
result
{256: <Response [200]>, 257: <Response [200]>, 258: <Response [200]>, 259: <Response [200]>, 260: <Response [200]>, 261: <Response [200]>, 262: <Response [200]>, 263: <Response [200]>, 264: <Response [200]>, 265: <Response [200]>, 266: <Response [200]>, 267: <Response [200]>, 268: <Response [200]>, 269: <Response [200]>, 270: <Response [200]>, 271: <Response [200]>, 272: <Response [200]>}
'''

print('-====================-')

print('[+] lower intruder test - option="lower", verbose=True')
rr = pp.sequencialIntruder(rawPacket, to=90, option='lower', verbose=True)
print(rr)
'''
result
{100: <Response [200]>, 99: <Response [200]>, 98: <Response [200]>, 97: <Response [200]>, 96: <Response [200]>, 95: <Response [200]>, 94: <Response [200]>, 93: <Response [200]>, 92: <Response [200]>, 91: <Response [200]>, 90: <Response [200]>}
'''
```
