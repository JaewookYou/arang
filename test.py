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