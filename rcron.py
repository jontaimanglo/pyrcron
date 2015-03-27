#!/usr/bin/python2.7
import re, ast, random, argparse, os
from time import time, strftime, sleep
from datetime import datetime
from cStringIO import StringIO
from Queue import Queue
from threading import Thread
try:
	import simplejson as json
except:
	import json
#local libraries
from lib.helper import sqlQuery, thisSystem, cleanAndLower, hashString, encrypt, decrypt, toUnicode

# non-standard library
_PARAMIKO = False
try:
        import paramiko
        _PARAMIKO = True
except Exception, err:
        print("[ERROR] Unable to import paramiko: %s" % err)
	exit(-1)
###
#	action = 0, attempt to run cron on system in the order they are provided, first success, return
#	action = 1, shuffle list of available systems, first success, return
#	action = 2, run cron on all configured systems at the same time
#	action = 3, if previous iteration of cron is running, clobber and start new; useful for long running
#		crons
###
class rcron:
    def __init__(self, test=False):
        self.dt = datetime.now()
        self.db = "rcron"
        self.cache_file = "/tmp/rcron.cache"
        self.cache_file_temp = "%s.tmp" % self.cache_file
        self.cache_stale_mins = 5 
        self.cache_file_key = "8a10465a559947c58983516a6ce179b6bd52e4df7b39aef75d43c7e27892450b"
        self.max_threads = 4
        self.auth = {}
        self.hosts = {}
        self.test = test
        if self.test:
            print("[INFO] Test only")

    def add(self, add_type=None, add_data={}):
		if not self._create():
			print("[ERROR] Unable to create rcron tables")
			return False
		if not add_type:
			return {"error": "no add type provided"}
		if add_type == "auth":
			auth_res = self._addAuth(add_data)
			if not auth_res:
				return {"error": auth_res}
		if add_type == "host":
			host_res = self._addHost(add_data)
			if not host_res:
				return {"error": host_res}
		if add_type == "cron":
			cron_res = self._addCron(add_data)
			if not cron_res:
				return {"error": cron_res}
		return True

    def _addAuth(self, auth_data):
		if not self._create():
			print("[ERROR] Unable to create rcron tables")
			return False
		if len(auth_data) == 0:
			return False
		if not isinstance(auth_data, list):
			auth_data = [auth_data]
		sql = "INSERT INTO rcron_auth (user, password, checksum) VALUES (%s, %s, %s)"
		sql_vals = []
		try:
			for k in auth_data:
				sql_vals.append((toUnicode(k.keys()[0]), toUnicode(k.values()[0]), toUnicode(hashString(k.values()[0], "sha256"))))
		except Exception, err:
			print("[ERROR] Unable to parse auth_data: %s" % err)
			return False
		try:
			if self.test:
				print("[SQL] %s, %s" %(sql, sql_vals))
			else:
				sqlQuery(sql, db=self.db, _params=sql_vals, bulk=True, commit=True, _raise=True)
		except Exception, err:
			print("[ERROR] Unable to add rcron auth data: %s" % err)
			return False
		return True

    def _addHost(self, host_data):
		if not self._create():
			print("[ERROR] Unable to create rcron tables")
			return False
		if len(host_data) == 0:
			return False
		if not isinstance(host_data, list):
			host_data = [host_data]
		_host_data = []
		for i, hd in enumerate(host_data):
			try:
				host = hd["host"]
			except:
				print("[WARN] No host provided")
				continue
			try:
				port = int(hd["port"])
			except:
				port = 22
			try:
				lport = int(hd["local_port"])
			except:
				lport = 22
			_host_data.append((toUnicode(host), toUnicode(port), toUnicode(lport)))	
		if len(_host_data) == 0:
			print("[WARN] No host data parsed")
			return False
		sql = "INSERT INTO rcron_hosts (host, port, local_port) VALUES (%s, %s, %s)"
		sql_vals = _host_data
		try:
			if self.test:
				print("[SQL] %s, %s" %(sql, sql_vals))
			else:
				sqlQuery(sql, db=self.db, _params=sql_vals, bulk=True, commit=True, _raise=True)
		except Exception, err:
			print("[ERROR] Unable to add rcron host data: %s" % err)
			return False
		return True

    def _addCron(self, cron_data):	
		if not self._create():
			print("[ERROR] Unable to create rcron tables")
			return False
		if len(cron_data) == 0:
			return False
		if not isinstance(cron_data, list):
			cron_data = [cron_data]
		_cron_data = []
		for cd in cron_data:
			try:
				cron_name = cleanAndLower(cd["name"])
			except:
				print("[WARN] Unable to parse cron name: %s" % err)
				continue
			try:
				cron_path = cleanAndLower(cd["path"])
			except Exception, err:
				print("[WARN] Unable to parse cron path: %s" % err)
				continue
			try:
				action = int(cd["action"])
			except:
				action = 0	
			try:
				enabled = int(cd["enabled"])
			except:
				enabled = 0
			try:
				cmin = self._sanitizeInterval(str(cd["min"]))
			except:
				try:
					if re.search("/", str(cd["min"])):
						continue
				except:
					cmin = "*"
			try:
				chour = self._sanitizeInterval(str(cd["hour"]))
			except:
				try:
					if re.search("/", str(cd["hour"])):
						continue
				except:
					chour = "*"
			try:
				cdom = self._sanitizeInterval(str(cd["dom"]))
			except:
				try:
					if re.search("/", str(cd["dom"])):
						continue
				except:
					cdom = "*"
			try:
				cmon = self._sanitizeInterval(str(cd["mon"]))
			except:
				try:
					if re.search("/", str(cd["mon"])):
						continue
				except:
					cmon = "*"
			try:
				cdow = self._sanitizeInterval(str(cd["dow"]))
			except:
				try:
					if re.search("/", str(cd["dow"])):
						continue
				except:
					cdow = "*"
			dt = datetime.strptime("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")
			try:
				users = cd["users"]
				for i, h in enumerate(cd["hosts"]):
					_h = self.rcronQuery("hosts", {"host": h})
					try:
						_h = int(_h[0][0])
						if not _h:
							continue
					except:
						continue
					userid = self.rcronQuery("auth", {"user": users[i]})
					try:
						userid = int(userid[0][0])
						if not userid:
							continue
					except:
						continue
					_cron_data.append((toUnicode(cron_name), toUnicode(cron_path), toUnicode(cmin), toUnicode(chour), toUnicode(cdom), toUnicode(cmon), toUnicode(cdow), toUnicode(enabled), toUnicode(_h), toUnicode(userid), toUnicode(action), dt))
			except Exception, err:
				print("[WARN] Unable to parse user and host data for cron: %s" % err)
				continue
		if len(_cron_data) == 0:
			print("[WARN] No cron data to add")
			return False
		sql = "INSERT IGNORE INTO rcron_crons (cron_name, cron_path, cron_min, cron_hour, cron_dom, cron_mon, cron_dow, enabled, host, user, action, last_run) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
		sql_vals = _cron_data
		try:
			if self.test:
				print("[SQL] %s, %s" %(sql, sql_vals))
			else:
				sqlQuery(sql, db=self.db, _params=sql_vals, bulk=True, commit=True, _raise=True)
		except Exception, err:
			print("[ERROR] Unable to add rcron cron data: %s" % err)
			return False
		return True

    def delete(self, delete_type=None, delete_data={}, clean=False):
		if not delete_type:
			print("[WARN] No delete type provided")
			return False
		delete_data = self._sanitizeFilterFields(delete_data)
		if len(delete_data) == 0:
			print("[WARN] No delete data provided")
		if delete_type == "cron":
			_crons = self.rcronQuery("crons", delete_data, ["id", "host", "user"])
			_ids = {}
			_hosts = {}
			_users = {}
			_delete = {}
			for c in _crons:
				_ids[c[0]] = 1
				try:
					_hosts[c[1]]
				except:
					_hosts[c[1]] = 1
					if clean:
						host_crons = self.rcronQuery("crons", {"host": c[1]})
						try:
							if len(host_crons) == 1:
								try:
									_delete["host"].append({"id": c[1]})
								except:
									_delete.update({"host": [{"id": c[1]}]})
						except:
							pass
				try:
					_users[c[2]]
				except:
					_users[c[2]] = 1
					if clean:
						user_crons = self.rcronQuery("crons", {"user": c[2]})
						try:
							if len(user_crons) == 1:
								try:
									_delete["auth"].appende({"id": c[2]})
								except:
									_delete.update({"auth": [{"id": c[2]}]})
						except:
							pass
			if len(_ids) > 0:
				ids = ["'%s'" % i for i in _ids.keys()]
				#print("[DEBUG] Attempting to delete crons: %s" % _ids.keys())
				sql = "DELETE FROM rcron_crons WHERE id IN (%s)" % ',' . join(ids)
				try:
					if self.test:
						print("[SQL] %s" % sql)
					else:
						sqlQuery(sql, db=self.db, commit=True)
					try:
						for dl in _delete["host"]:
							self.delete("host", dl, clean=clean)
					except:
						pass
					try:
						for dl in _delete["auth"]:
							self.delete("auth", dl, clean=clean)
					except:
						pass 
				except Exception, err:
					print("[ERROR] Unable to delete from rcron crons table: %s" % err)
					return False
			else:
				print("[INFO] No matching crons for delete")
				return False
		elif delete_type == "host":
			_hosts = self.rcronQuery("hosts", delete_data)
			_ids = {h[0]: 1 for h in _hosts}
			if len(_ids) > 0:
				ids = ["'%s'" % i for i in _ids.keys()]
				#print("[DEBUG] Attempting to delete hosts: %s" % _ids.keys())
				sql = "DELETE FROM rcron_hosts WHERE id IN (%s)" % ',' . join(ids)
				try:
					if self.test:
						print("[SQL] %s" % sql)
					else:
						sqlQuery(sql, db=self.db, commit=True)
				except Exception, err:
					print("[ERROR] Unable to delete from rcron hosts table: %s" % err)
					return False
			else:
				print("[INFO] No matching hosts for delete")
				return False
		elif delete_type == "auth":
			_users = self.rcronQuery("auth", delete_data)
			_ids = {u[0]: 1 for u in _users}
			if len(_ids) > 0:
				ids = ["'%s'" % i for i in _ids.keys()]
				#print("[DEBUG] Attempting to delete users: %s" % _ids.keys())
				sql = "DELETE FROM rcron_auth WHERE id IN (%s)" % ',' . join(ids)
				try:
					if self.test:
						print("[SQL] %s" % sql)
					else:
						sqlQuery(sql, db=self.db, commit=True)
				except Exception, err:
					print("[ERROR] Unable to delete from rcron hosts table: %s" % err)
					return False
			else:
				print("[INFO] No matching hosts for delete")
				return False
		else:
			print("[WARN] Invalid type provided to delete: %s" % repr(delete_type))
			return False
		return True

	###
	#
	# TODO: Still rudimentary; still needs some sanity checks for what the user is providing
	###
    def update(self, update_type=None, select_data={}, update_data={}):
		if not update_type:
			print("[WARN] No updated type provided")
			return False
		if len(select_data) == 0:
			print("[WARN] No select data provided")
			return False
		if len(update_data) == 0:
			print("[WARN] No update data provided")
			return False
		if update_type == "cron":
			cron_ids = self.rcronQuery("crons", select_data)
			_ids = {c[0]: 1 for c in cron_ids}	
			ids = ["'%s'" % i for i in _ids.keys()]
			sql = "UPDATE rcron_crons SET " + ',' . join(toUnicode(k) + "=%(" + k + ")s" for k in update_data.keys()) + " WHERE id IN (%s)" % ',' . join(ids)
			try:
				if self.test:
					print("[SQL] %s, %s" %(sql, update_data))
				else:
					sqlQuery(sql, db=self.db, _params=update_data, commit=True, _raise=True)
			except Exception, err:
				print("[ERROR] Unable to update rcron crons: %s" % err)
				return False
		elif update_type == "host":
			host_ids = self.rcronQuery("hosts", select_data)
			_ids = {h[0]: 1 for h in host_ids}	
			ids = ["'%s'" % i for i in _ids.keys()]
			sql = "UPDATE rcron_hosts SET " + ',' . join(toUnicode(k) + "=%(" + k + ")s" for k in update_data.keys()) + " WHERE id IN (%s)" % ',' . join(ids)
			try:
				if self.test:
					print("[SQL] %s, %s" %(sql, update_data))
				else:
					sqlQuery(sql, db=self.db, _params=update_data, commit=True, _raise=True)
			except Exception, err:
				print("[ERROR] Unable to update rcron hosts: %s" % err)
				return False
		elif update_type == "auth":
			user_ids = self.rcronQuery("auth", select_data)
			_ids = {u[0]: 1 for u in user_ids}	
			ids = ["'%s'" % i for i in _ids.keys()]
			sql = "UPDATE rcron_auth SET " + ',' . join(toUnicode(k) + "=%(" + k + ")s" for k in update_data.keys()) + " WHERE id IN (%s)" % ',' . join(ids)
			try:
				if self.test:
					print("[SQL] %s, %s" %(sql, update_data))
				else:
					sqlQuery(sql, db=self.db, _params=update_data, commit=True, _raise=True)
			except Exception, err:
				print("[ERROR] Unable to update rcron auth: %s" % err)
				return False
		else:
			print("[ERROR] Invalid update type provided: %s" % repr(update_type))
			return False
		return True
	
    def rcronQuery(self, _table, filter_fields, return_values=["id"]):
		if len(filter_fields) == 0:
			print("[WARN] No filter fields provided")
			return False
		rcron_info = True
		sql = "SELECT " + ',' .join(return_values) + " FROM rcron_{} WHERE ".format(_table) + ' AND ' .join(k + "=%(" + k + ")s" for (k, v) in filter_fields.iteritems())
		try:
			if self.test:
				print("[SQL] %s, %s" %(sql, filter_fields))
			else:
				rcron_info = sqlQuery(sql, db=self.db, _params=filter_fields, multi=True, _raise=True)
		except Exception, err: 
			print("[ERROR] Unable to get rcron info: %s" % err)
			return False
		return rcron_info 

    def _sanitizeInterval(self, interval):
		if re.search("/", interval):
			if re.search("\*(\s+)?/(\s+)?[1-9]+", interval):
				interval = cleanAndLower(interval, doLower=False)
				interval = re.sub("\s+", "", interval)
			else:
				print("[ERROR] Invalid interval format (%s)" % repr(interval))
				raise Exception("Invalid interval format, must be */[0-9]+")
		return interval	

    def _sanitizeFilterFields(self, filter_fields):
		try:
			ix = filter_fields.values().index("*")
			if ix >= 0:
				k = filter_fields.keys()[ix]
				try:
					del filter_fields[k]
				except Exception, err:
					print("[ERROR] Unable to sanitize filter fields (%s): %s" %(repr(filter_fields), err))
					return {}
				return self._sanitizeFilterFields(filter_fields)
		except:
			pass
		return filter_fields

    def testHost(self, userid, hostid="all"):
		run_results = self._getInfo(ignore_cache=True)
		cmd = "ls -l"
		try:
			self.auth[str(userid)]
		except:
			return {"error": "invalid userid"}
		if hostid == "all":
			hostid = self.hosts.keys()
		else:
			try:
				self.hosts[str(hostid)]
				hostid = [hostid]
			except:
				return {"error": "invalid hostid"}
		test_results = {"success": {}, "failure": {}}
		for h in hostid:
			#print("[DEBUG] testHost, (host, user, cmd): (%s, %s, %s)" %(h, userid, cmd))
			_h = self._runCron(cmd, h, userid, 0)
			try:
				if _h[str(h)][0]:
					test_results["success"].update({self.hosts[str(h)][0]: _h[str(h)][1]})
				else:
					test_results["failure"].update({self.hosts[str(h)][0]: _h[str(h)][2]})
			except Exception, err:
				test_results["failure"].update({self.hosts[str(h)][0]: str(err)})
		return test_results
	
    def show(self, show_type="all"):
		run_results = self._getInfo(ignore_cache=True)
		if show_type == "auth":
			run_results = {ak: av[0] for ak, av in self.auth.iteritems()}
		elif show_type == "hosts":
			run_results = {hk: hv[0] for hk, hv in self.hosts.iteritems()}
		elif show_type == "crons":
			_run_results = {}
			for rr in run_results:
				t_hosts = [self.hosts[str(r)][0] for r in rr[8]]
				t_users = [self.auth[str(r)][0] for r in rr[9]]
				_run_results[rr[0]] = list(rr[1:11])
				_run_results[rr[0]][7] = t_hosts
				_run_results[rr[0]][8] = t_users
			run_results = _run_results
		return run_results

    def run(self, cron_id=None):
		if not self._create():
			print("[ERROR] Unable to create rcron tables")
			return False
		if not _PARAMIKO:
			print("[ERROR] Paramiko library missing or not found.  Exiting")
			return False
		current_time = self.dt.strftime("%w_%m_%d_%H_%M").split("_")
		_now_dow = current_time[0]
		_now_mon = current_time[1]
		_now_dom = current_time[2]
		_now_hour = current_time[3]
		_now_min = current_time[4]
		run_results = self._getInfo()
		if not run_results:
			return False
		#0, 	1,	2,		3,	4,	5,		6,	7, 	8,  9,    10	  11
		#id, cron_name, cron_path, cron_min, cron_hour, cron_dom, cron_mon, cron_dow, host, user, action, enabled
		self.cronQ = Queue()
		#print("[DEBUG] cronQ created")
		for i in range(self.max_threads):
			try:
				cronWorker = Thread(target=self._cronThreadWrapper, args=(self.cronQ,))
				cronWorker.setDaemon(True)
				cronWorker.start()
				#print("[DEBUG] cronWorker thread %d created" % i)
			except Exception, err:
				print("[WARN] Unable to create cronWorker thread: %s" % err)
		cronsToRun = False
		for rr in run_results:
			try:
				if int(rr[0]) == int(cron_id):
					#print("[DEBUG] Manually adding to cronQ: %s, %s, %s, %s, %s" %(rr[1], rr[2], rr[8], rr[9], rr[10]))
					self.cronQ.put([rr[1], rr[2], rr[8], rr[9], rr[10]])
					cronsToRun = True
					continue
			except:
				pass
			if rr[11] == 0:
				continue
			if self._intervalCheck(rr[7], _now_dow):
				if self._intervalCheck(rr[6], _now_mon):
					if self._intervalCheck(rr[5], _now_dom):
						if self._intervalCheck(rr[4], _now_hour):
							if self._intervalCheck(rr[3], _now_min):
								#print("[DEBUG] Adding to cronQ: %s, %s, %s, %s, %s" %(rr[1], rr[2], rr[8], rr[9], rr[10]))
								self.cronQ.put([rr[1], rr[2], rr[8], rr[9], rr[10]])
								cronsToRun = True
		self.cronQ.join()
		if cronsToRun:
			print("[INFO] All crons completed")
		return True

    def _cronThreadWrapper(self, cq):
		while True:
			c = cq.get()
			cron_name = c[0]
			#print("[DEBUG] From cronQ: %s" % c)
			results = self._runCron(c[1], c[2], c[3], c[4])
			for rk, rv in results.iteritems():
				_now = self.dt.strftime("%Y-%m-%d %H:%M:%S")
				if rv[0]:
					print("[INFO] cron (%s) successfully run on host (%s)" %(cron_name, self.hosts[str(rk)][0]))
				else:
					print("[INFO] cron (%s) failed to run on host (%s)" %(cron_name, self.hosts[str(rk)][0]))
				cron_success_sql = "UPDATE rcron_crons SET last_run=%s, duration=%s, errors=%s WHERE cron_name=%s AND host=%s"
				cron_success_vals = (_now, rv[1], rv[2], cron_name, rk)
				try:
					if self.test:
						print("[SQL] %s, %s" %(cron_success_sql, cron_success_vals))
					else:
						sqlQuery(cron_success_sql, db=self.db, _params=cron_success_vals, commit=True)
				except Exception, err:
					print("[WARN] unable to update last run: %s" % err)
			cq.task_done()	

    def _getInfo(self, ignore_cache=False):
		run_results = False
		if not ignore_cache:
			if os.path.exists(self.cache_file):
				mtime = datetime.fromtimestamp(os.path.getctime(self.cache_file))
				if (self.dt - mtime).total_seconds() < (self.cache_stale_mins * 60):
					#print("[DEBUG] Loading rcron cache file: %s" % self.cache_file)
					try:
						with open(self.cache_file, "rb") as cyphertext, open(self.cache_file_temp, "wb") as plaintext:
							decrypt(cyphertext, plaintext, self.cache_file_key)
						try:
							with open(self.cache_file_temp, "r") as cf:
								data = json.load(cf)
							self.auth = data["auth"]
							self.hosts = data["host"]
							run_results = data["run_results"]
						except Exception, err:
							print("[WARN] Unable to load cache file at '%s': %s" %(self.cache_file_temp, err))
						try:
							os.remove(self.cache_file_temp)
						except Exception, err:
							print("[ERROR] Unable to remove plaintext cache file (%s): %s" %(self.cache_file_temp, err))
						if run_results:
							return run_results
					except Exception, err:
						print("[WARN] Unable to decrypt local cache file (%s): %s" %(self.cache_file, err))
		sql = "SELECT rcron_crons.id, cron_name, cron_path, cron_min, cron_hour, cron_dom, cron_mon, cron_dow, action, rcron_crons.host, rcron_hosts.host, rcron_hosts.port, rcron_hosts.local_port, rcron_crons.user, rcron_auth.user, rcron_auth.password, enabled FROM rcron_crons, rcron_hosts, rcron_auth WHERE rcron_crons.user=rcron_auth.id AND rcron_crons.host=rcron_hosts.id ORDER BY cron_name"
		try:
			cron_data = sqlQuery(sql, db=self.db, multi=True)
		except Exception, err:
			print("[ERROR] Unable to retrieve rcron data: %s" % err)
			return False
		#	0		1	2	3		4	5	6	7	  8	   9	   		10	 		11
		#rcron_crons.id, cron_name, cron_path, cron_min, cron_hour, cron_dom, cron_mon, cron_dow, action, rcron_crons.host, rcron_hosts.host, rcron_hosts.port
		#	12		   13	 14			15 		16
		#, rcron_hosts.local_port, user, rcron_auth.user, rcron_auth.password, enabled
		crons = {}
		for cd in cron_data:
			try:
				self.auth[str(cd[13])]
			except:
				self.auth[str(cd[13])] = [cd[14], cd[15]]
			try:
				self.hosts[str(cd[9])]
			except:
				self.hosts[str(cd[9])] = [cd[10], cd[11], cd[12]]
			try:
				#if action is 2, then all crons should be run at the same time
				if cd[8] == 2:
					raise Exception("action is 2")
				crons[cd[1]][7].append(cd[9])
				crons[cd[1]][8].append(cd[13])
			except:
				_t = []
				_t = [cd[0]] + list(cd[2:9])
				_t.insert(7, [cd[9]])
				_t.insert(8, [cd[13]])
				_t.append(cd[16])
				_key = cd[1]
				if cd[8] == 2:
					_key = "%s:%s" %(cd[1], cd[0])
				crons.update({_key: _t})
		run_results = []
		for ck, cv in crons.iteritems():
			_t = cv
			try:
				_key = ck.split(":")[0]
			except:
				_key = ck
			_t.insert(1, _key)
			run_results.append(tuple(_t))
		if not ignore_cache:
			try:
				with open(self.cache_file_temp, "w") as cf:
					json.dump({"auth": self.auth, "host": self.hosts, "run_results": run_results}, cf)
				try:
					with open(self.cache_file_temp, "rb") as plaintext, open(self.cache_file, "wb") as cyphertext:
						encrypt(plaintext, cyphertext, self.cache_file_key)
				except Exception, err:
					print("[WARN] Unable to encrypt local cache file (%s): %s" %(self.cache_file_temp, err))
				try:
					os.remove(self.cache_file_temp)
				except Exception, err:
					print("[ERROR] Unable to remove plaintext cache file (%s): %s" %(self.cache_file_temp, err)) 
			except Exception, err:
				print("[WARN] Unable to write cache file '%s': %s" %(self.cache_file, err))
		return run_results

    def _intervalCheck(self, cron_val, now_val):
		#print("[_intervalCheck] %s, %s" %(cron_val, now_val))
		if cron_val == "*":
			return True
		elif re.search("\*/[0-9]+", cron_val):
			try:
				_cron_val = int(cron_val.split("/")[1])
			except Exception, err:
				print("[ERROR] Unable to cast cron interval (%s) to int: %s" %(repr(cron_val), err))
				return False
			if _cron_val <= 0:
				print("[WARN] Cron attempted interval is <= 0: %s" % repr(cron_val))
				return False
			if int(now_val) % _cron_val == 0:
				return True
		elif int(cron_val) == int(now_val):
			return True
		return False

    def _runCron(self, cron_path, hosts, users, action):
		if not isinstance(hosts, list):
			hosts = [hosts]
		if not isinstance(users, list):
			users = [users]
		runOnAll = False
		if action == 1:
			#random shuffle hosts
			random.shuffle(hosts)
		elif action == 2:
			runOnAll = True
		success = False
		duration = None
		errors = None
		results = {}
		for i, host in enumerate(hosts):
			_host, _port, _user, _passwd = self._parseConnectionDetails(host, users[i])
			if not (_host or _port or _user or _passwd or cron_path):
				continue
			try:
				self.disabled[thisSystem(_host)]
				#print("[DEBUG] Systems' (%s) host (%s) is disabled; will not run cron (%s) on it" %(_host, thisSystem(_host), cron_path))
				continue
			except:
				pass
			checksum = hashString("%s,%s,%s,%s" %(cron_path, _host, _user, action), "sha256")
			checksum_file = "/tmp/%s.rcron" % checksum
			if os.path.exists(checksum_file):
				if int(action) == 3:
					print("[INFO] Previous cron for %s@%s:%s is still running (%s); attempting to kill" %(_user, _host, cron_path, checksum_file))
					if not self._checkRemoteProcesses(_host, _port, _user, _passwd, cron_path, kill=True):
						errors = "Unable to kill previous running cron"
						return {host :[False, duration, errors]}
				else:
					print("[INFO] Previous cron for %s@%s:%s is still running: %s" %(_user, _host, cron_path, checksum_file))
					return {host :[False, duration, errors]}
			with open(checksum_file, "w") as cfile:
				cfile.write(self.dt.strftime("%Y-%m-%dT%H:%M:%S"))
			#print("[DEBUG] rcron file created, %s" % checksum_file) 
			try:
				conn_res, errors = self.connect(_host, _port, _user, _passwd, cron_path)
				if not conn_res or errors:
					print("[WARN] Unable to run cron (%s) on host (%s): %s" %(cron_path, _host, errors))
				else:
					success = host
					duration = conn_res
			except Exception, err:
				print("[ERROR] Unable to run cron (%s) on host (%s): %s" %(cron_path, _host, err))
				errors = str(err)
			try:
				os.remove(checksum_file)
			except Exception, err:
				print("[WARN] Unable to remove file (%s): %s" %(checksum_file, err))
			if success:
				if not runOnAll:
					return {host: [True, duration, errors]}
				else:
					results.update({host: [True, duration, errors]})
			else:
				if not runOnAll:
					return {host: [False, duration, errors]}
				else:
					results.update({host: [False, duration, errors]})
		return results

    def _checkRemoteProcesses(self, _host, _port, _user, _passwd, proc_name, kill=False):
		cmd = "ps -eaf"
		conn_res, std_out = self.connect(_host, _port, _user, _passwd, cmd, getstdout=True)
		if not conn_res or not std_out:
			print("[WARN] Unable to find running processes on host: %s" % _host) 
			return False
		proc_rgx = re.compile(re.escape(proc_name), re.IGNORECASE)
		ps_list = std_out.split("\n")
		ps_ids = []
		for ps in ps_list:
			if proc_rgx.search(ps):
				_ps = re.split("\s+", ps)
				if not _ps[1] in ps_ids:
					ps_ids.append(_ps[1])	
		if len(ps_ids) > 0:
			#print("[DEBUG] Found process ids (%s) for process (%s) on host (%s)" %(',' . join(ps_ids), proc_name, _host))
			if kill:
				for psi in ps_ids:
					cmd = "kill -9 %d" % int(psi)
					conn_res, errors = self.connect(_host, _port, _user, _passwd, cmd)
					if not conn_res	or errors:
						print("[WARN] Unable to kill process (%s) with id (%s) on host (%s): %s" %(proc_name, psi, _host, errors))
						return False
					#print("[DEBUG] Successfully killed process (%s) with id (%s)  on host (%s)" %(proc_name, psi, _host))
		return True	
	
    def _parseConnectionDetails(self, hostid, userid):
		_host = None
		_port = None
		_user = None
		_passwd = None
		if hostid:
			host = str(hostid)
			try:
				_host = self.hosts[host][0]
				_port = self.hosts[host][1]
				_local_port = self.hosts[host][2]
				if _local_port:
					if thisSystem(_host) == thisSystem():
						_port = _local_port
			except Exception, err:
				print("[ERROR] Unable to parse connection host details for (%s): %s" %(host, err))
			try:
				_user = self.auth[str(userid)][0]
				_passwd = self.auth[str(userid)][1]
			except Exception, err:
				print("[ERROR] Unable to parse connection authentication details for (%s): %s" %(host, err))
		else:
			print("[WARN] Unable to parse connection details; no host provided")
		return _host, _port, _user, _passwd

    def connect(self, host, port, user, passwd, cmd, getstdout=False):
		if not (host or port or user or passwd or cmd):
			return False
		if self.test:
			return 0.5 
		start_time = time()
		#ssh into system, execute cmd
		conn_res = False
		errors = None
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
			if re.search("^(-)+?BEGIN RSA PRIVATE KEY(-)+?", passwd, re.IGNORECASE):
				try:
					_passwd = StringIO(passwd)
				except Exception, err:
					print("[ERROR] Unable to read in certificate: %s" % err)
					#return False, "Unable to read in certificate: %s" % err
					raise Exception("Unable to read in certificate: %s" % err)
				_passwd.seek(0)
				pk = paramiko.RSAKey.from_private_key(_passwd)
                                #print("[DEBUG] Attempting ssh connection using private key from string")
                                ssh.connect(hostname=host, port=int(port), username=user, pkey=pk)
			elif os.path.isfile(passwd):
				pk = paramiko.RSAKey.from_private_key_file(passwd)
                                #print("[DEBUG] Attempting ssh connection using private key from file")
                                ssh.connect(hostname=host, port=int(port), username=user, pkey=pk)
			else:
				#print("[DEBUG] Attempting ssh connection using password")
				ssh.connect(hostname=host, port=int(port), username=user, password=passwd)
			try:
				#print("[DEBUG] Attempting connection: %s@%s:%s:%s" %(user, host, port, cmd))
				stdin, stdout, stderr = ssh.exec_command(cmd)
				status = stdout.channel.recv_exit_status()
				_stderr = stderr.read()
				if not _stderr == "":
					raise Exception(str(_stderr))
				if status == 0:
					if getstdout:
						errors = stdout.read()
					conn_res = True
				#print("[DEBUG] connection status: %s, connection results: %s" %(status, conn_res))
			except Exception, err:
				print("[ERROR] Unable to run command (%s) on host (%s): %s" %(cmd, host, err))
				errors = "Unable to run command (%s) on host (%s): %s" %(cmd, host, err) 
		except Exception, err:
			print("[ERROR] Unable to connect to %s@%s:%s to run %s: %s" %(user, host, port, cmd))
			errors = "Unable to connect to %s@%s:%s to run %s: %s" %(user, host, port, cmd, err) 
		try:
			ssh.close()
		except Exception, err:
			print("[WARN] Unable to close connection: %s" % err)
		end_time = time() - start_time
		if conn_res:
			conn_res = end_time
		return conn_res, errors

    def _create(self):
                check_sql = "SHOW TABLES LIKE 'rcron_auth'"
                try:
                        table_exists = sqlQuery(check_sql, db=self.db)
                        if not table_exists:
                                try:
					sql = "CREATE TABLE IF NOT EXISTS rcron_auth (id INT AUTO_INCREMENT, user VARCHAR(255) NOT NULL, password TEXT NOT NULL, checksum VARCHAR(64), PRIMARY KEY(id), UNIQUE KEY(user, checksum)) DEFAULT CHARACTER SET='utf8' DEFAULT COLLATE 'utf8_general_ci'"
                                        sqlQuery(sql, db=self.db, commit=True, _raise=True)
                                except Exception, err:
                                        print("[ERROR] Unable to create rcron_auth table: %s" % err)
                                        return None
                except Exception, err:
                        print("[ERROR] Unable to determine if rcron_auth table exists: %s" % err)
                        return False
                check_sql = "SHOW TABLES LIKE 'rcron_hosts'"
                try:
                        table_exists = sqlQuery(check_sql, db=self.db)
                        if not table_exists:
                                try:
					sql = "CREATE TABLE IF NOT EXISTS rcron_hosts (id INT AUTO_INCREMENT, host VARCHAR(255) NOT NULL, port INT NOT NULL DEFAULT 22, local_port INT NOT NULL DEFAULT 22, PRIMARY KEY(id), UNIQUE KEY(host, port, local_port)) DEFAULT CHARACTER SET='utf8' DEFAULT COLLATE 'utf8_general_ci'"
                                        sqlQuery(sql, db=self.db, commit=True, _raise=True)
                                except Exception, err:
                                        print("[ERROR] Unable to create rcron_hosts table: %s" % err)
                                        return None
                except Exception, err:
                        print("[ERROR] Unable to determine if rcron_hosts table exists: %s" % err)
                        return False
                check_sql = "SHOW TABLES LIKE 'rcron_crons'"
                try:
                        table_exists = sqlQuery(check_sql, db=self.db)
                        if not table_exists:
                                try:
					sql = "CREATE TABLE IF NOT EXISTS rcron_crons (id INT AUTO_INCREMENT, cron_name VARCHAR(255) NOT NULL, cron_path VARCHAR(255) NOT NULL, cron_min VARCHAR(255) NOT NULL DEFAULT '*', cron_hour VARCHAR(255) NOT NULL DEFAULT '*', cron_dom VARCHAR(255) NOT NULL DEFAULT '*', cron_mon VARCHAR(255) NOT NULL DEFAULT '*', cron_dow VARCHAR(255) NOT NULL DEFAULT '*', enabled TINYINT DEFAULT 1 NOT NULL, host INT NOT NULL, user INT NOT NULL, action TINYINT NOT NULL DEFAULT 0, last_run TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, duration DOUBLE(8, 2) NULL, errors VARCHAR(255) NULL, PRIMARY KEY(id), FOREIGN KEY (host) REFERENCES rcron_hosts(id), FOREIGN KEY (user) REFERENCES rcron_auth(id), UNIQUE KEY(cron_name, cron_path, host, user)) DEFAULT CHARACTER SET='utf8' DEFAULT COLLATE 'utf8_general_ci'"
                                        sqlQuery(sql, db=self.db, commit=True, _raise=True)
                                except Exception, err:
                                        print("[ERROR] Unable to create rcron_crons table: %s" % err)
                                        return None
                except Exception, err:
                        print("[ERROR] Unable to determine if rcron_crons table exists: %s" % err)
                        return False
                return True

def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("-c", "--create", action="store_true", default=False, help="create database table if necessary")
        parser.add_argument("-t", "--test", action="store_true", default=False, help="test only; do not write to SQL")
        parser.add_argument("-n", "--host", default=None, help="provide a host id to test connection to; 'all' will test all")
        parser.add_argument("-u", "--auth", default=None, help="used in combination with --host to provide the user id to connect to --host with")
        parser.add_argument("-s", "--show", default=None, help="print to screen items of interest (crons, hosts, auth);'all' will print all entries")
        parser.add_argument("-r", "--run", action="store_true", default=False, help="run crons")
	parser.add_argument("-i", "--cronid", default=None, help="used in combination with --run to manually run a cron; find id via --show crons")
       	parser.add_argument("-a", "--add_auth", default=None, help="add new auth entry: [{'user': <user>, 'password': <password>}]")
       	parser.add_argument("-o", "--add_host", default=None, help="add new host entry: [{'host': <host>, 'user': <user>, ('port': <port>, 'local_port': <local_port>)}]")
       	parser.add_argument("-x", "--add_cron", default=None, help="add new cron entry: [{'name': <cron_name>, 'path': <cron_path>, 'hosts': <[hosts]>, 'users': <[users]>, ('enabled': <0|1>, 'action': <0|1>, 'min': <min>, 'hour': <hour>', 'dom': <dom>, 'mon': <mon>, 'dow': <dow>)}]")
        args = parser.parse_args()
	r = rcron(args.test)
	if args.create:
		print r._create()
	elif args.show:
		try:
			if not args.show.lower() in ["auth", "hosts", "crons", "all"]:
				print("[ERROR] Invalid --show argument")
				exit(-1)
		except:
			print("[ERROR] Invalid --show argument")
			exit(-1)
		print json.dumps(r.show(args.show), indent=4)
	elif args.run:
		r.run(cron_id=args.cronid)
		sleep(1)
	elif args.add_auth:
		print r.add("auth", args.add_auth)
	elif args.add_host:
		print r.add("host", args.add_host)
	elif args.add_cron:
		print r.add("cron", args.add_cron)
	elif args.host:
		if not args.auth:
			print("[ERROR] Must provide --auth hostid")
			exit(-1)
		if not re.search("^[0-9]+$", str(args.auth)):
			print("[ERROR] --auth userid must be an integer")
			exit(-1)
		if not re.search("^[0-9]+$", str(args.host)):
			print("[ERROR] --host hostid must be an integer")
			exit(-1)
		print r.testHost(args.auth, args.host)

if __name__ == "__main__":
        main()
