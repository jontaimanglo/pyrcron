#!/usr/bin/python2.7
from time import sleep
import simplejson as json
from pyrcron import pyrcron
from lib.helper import hashString
r = pyrcron()

test_rsa = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=
-----END RSA PRIVATE KEY-----
"""

auth = [{"test_user": test_rsa}]
print r.add("auth", auth)
print r.add("auth", [{"test_user2": "im@p@ssw0rd"}])

host = [{"host": "sys1.local", "port": 2222}, {"host": "sys2.local", "port": 22}, {"host": "sys3.local"}] 
print r.add("host", host)

'''
0 4 * * * python /path/to/script.py --arg1 --arg2
0 5 * * * python /path/to/script2.py --arg1
0 */6 * * * python /path/to/script3.py --arg1 --arg2 --arg3
0 0 * * * python /path/to/script4.py
'''

cron = [{"name": "result_stats", "path": "python /path/to/script.py --arg1 --arg2", "hosts": ["sys1.local", "sys2.local", "sys3.local"], "users": ["test_user", "test_user", "test_user"], "enabled": 0, "min": "00", "hour": "4"}]
print r.add("cron", cron)

cron = [{"name": "filter_stats", "path": "python /path/to/script2.py --arg1", "hosts": ["sys1.local", "sys2.local", "sys3.local"], "users": ["test_user", "test_user", "test_user"], "enabled": 0, "min": "00", "hour": "5", "action": 1}]
print r.add("cron", cron)

cron = [{"name": "uri_and_email_trends", "path": "python /path/to/script3.py --arg1 --arg2 --arg3", "hosts": ["sys1.local", "sys2.local", "sys3.local"], "users": ["test_user", "test_user", "test_user"], "enabled": 0, "min": "00", "hour": "*/6", "action": 2}]
print r.add("cron", cron)

cron = [{"name": "attachment_trends", "path": "python /path/to/script4.py", "hosts": ["sys1.local", "sys2.local", "sys3.local"], "users": ["test_user", "test_user", "test_user"], "enabled": 0, "min": "00", "hour": "0", "action": 3}]
print r.add("cron", cron)

print json.dumps(r.show(), indent=4)
