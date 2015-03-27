#!/usr/bin/python2.7
import os
import re
import random
import hashlib
import inspect
import traceback
import mysql.connector
from time import sleep
from Crypto.Cipher import AES
from Crypto import Random
try:
	import simplejson as json
except:
	import json

def toUnicode(v):
        if not v:
                return v
        if isinstance(v, unicode) or isinstance(v, (int, long)):
                return v
        try:
                s = unicode(v, "ascii", "ignore")
        except Exception, err:
                s = v
                print("[WARN] Unable to encode to unicode (%s): %s" %(repr(v), err))
        return s

def cleanAndLower(v, doLower=True):
        if not v:
                return None
        if not isinstance(v, str):
                v = "%s" % v
        v = v.strip('\r\n')
        v = re.sub('(^\s+|\s+$)', '', v)
        if doLower:
                try:
                        v = v.lower()
                except:
                        pass
        return v

def hashString(s, hasher):
        if isinstance(hasher, basestring):
                hasher = hashlib.new(hasher)
        hasher.update(s)
        return hasher.hexdigest()

def sqlQuery(_sql, _params=None, bulk=False, multi=False, commit=False, db=None, _raise=False):
        conn, curs = dbConnect(db)
        if not conn or not curs:
                return False
        resp = False
        rse = False
        try:
                if not bulk:
                        curs.execute(_sql, _params)
                else:
                        curs.executemany(_sql, _params)
                if commit:
                        conn.commit()
                        resp = curs.lastrowid
                else:
                        if multi:
                                resp = curs.fetchall()
                        else:
                                resp = curs.fetchone()
        except Exception, err:
                conn.rollback()
                #print("[DEBUG] Unable to execute sql '%s', '%s': %s" %(_sql, _params, err))
                print("[ERROR] Unable to execute sql: %s" % err)
                rse = str(err)
        curs.close()
        conn.close()
        if _raise and rse:
                raise Exception(rse)
        return resp

def dbConnect(db):
	db_host = "127.0.0.1"
	db_user = "root"
	db_passwd = "root"
	ssl_ca = None #"/path/to/ca"
	ssl_cert = None #"/path/to/cert"
	ssl_key = None #"/path/to/key"
	max_pools = 2
	pool_size = 4
        try:
                config = {
                        "host": db_host,
                        "user": db_user,
                        "passwd": db_passwd,
                        "db":db,
                        #"ssl_ca": ssl_ca,
                        #"ssl_cert": ssl_cert,
                        #"ssl_key": ssl_key,
                        #"ssl_verify_cert": False,
                        "buffered": True
                }
                conn = None
                num_tries = 0
                while True:
                        p_name = "pool_%s_%s" %(db, random.randint(0, max_pools))
                        try:
                                conn = mysql.connector.connect(pool_name=p_name, pool_size=pool_size, **config)
                                curs = conn.cursor()
                                return conn, curs
                        except mysql.connector.PoolError as e:
                                num_tries = num_tries + 1
                                t = inspect.getframeinfo(inspect.stack()[1][0])
                                if t.function == 'sqlQuery':
                                        t = inspect.getframeinfo(inspect.stack()[2][0])
                                calling_func_info = 'filename=%s, lineno=%s, function=%s' %(t.filename, t.lineno, t.function)
                                if num_tries == 1000:
                                        print("[ERROR] dbConnect has tried to get loop 1000 times. Called from %s" %(calling_func_info))
                                        print("dbConnect traceback")
                                sleep(0)
        except Exception, err:
                print("[ERROR] Unable to connect to MySQL server with '%s@%s': %s" %(db_user, db_host, traceback.format_exc()))
                try:
                        fdcount = 0
                        for root, dirs, files in os.walk("/proc/%s/fd" % os.getpid()):
                                fdcount += len(files)
                        #print("[DEBUG] Current file descriptor count: %s" % fdcount)
                except Exception, err:
                        print("[ERROR] Unable to get fd count: %s" % err)
        return None, None

def thisSystem(this_system):
	sys = ""
        try:
                sys = "." . join(this_system.split(".")[1:])
        except Exception, err:
                print("[WARN] Unable to determine this systems name: %s" % err)
        return sys

# http://stackoverflow.com/questions/16761458/how-to-aes-encrypt-decrypt-files-using-python-pycrypto-in-an-openssl-compatible
def derive_key_and_iv(password, salt, key_length, iv_length):
        d = d_i = ''
        while len(d) < key_length + iv_length:
                d_i = md5(d_i + password + salt).digest()
                d += d_i
        return d[:key_length], d[key_length:key_length+iv_length]

# http://stackoverflow.com/questions/16761458/how-to-aes-encrypt-decrypt-files-using-python-pycrypto-in-an-openssl-compatible 
def decrypt(in_file, out_file, password, key_length=32):
        bs = AES.block_size
        salt = in_file.read(bs)[len('Salted__'):]
        key, iv = derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = ''
        finished = False
        while not finished:
                chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
                if len(next_chunk) == 0:
                        padding_length = ord(chunk[-1])
                        chunk = chunk[:-padding_length]
                        finished = True
                out_file.write(chunk)

def encrypt(in_file, out_file, password, key_length=32):
        bs = AES.block_size
        salt = Random.new().read(bs - len('Salted__'))
        key, iv = derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out_file.write('Salted__' + salt)
        finished = False
        while not finished:
                chunk = in_file.read(1024 * bs)
                if len(chunk) == 0 or len(chunk) % bs != 0:
                        padding_length = (bs - len(chunk) % bs) or bs
                        chunk += padding_length * chr(padding_length)
                        finished = True
                out_file.write(cipher.encrypt(chunk))
