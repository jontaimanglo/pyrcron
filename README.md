# rcron
Remote cron (via ssh)

## requirements
* paramiko
  * http://www.paramiko.org/

* mysql.connector
  * http://dev.mysql.com/downloads/connector/python/

## why?
I was tired of managing multiple crons on multiple systems, so I wrote this quick code 
to consolidate and automate this by securely (via ssh) connecting to different systems to
run scripts.

## how?
rcron is pretty basic, but any cron will require at least 3 items: auth, system, and a cron.
* auth: 
  * username: username used to connect to a system and run cron under
  * password: this can be a string, a path to a id_rsa file, or the contents
of the id_rsa file)
* system: 
  * host: name or ip of system to connect to
  * port: port to connect to
  * local_port: optional argument; this is used if system is determined to be on same network.
    * NOTE: this is pretty rudimentary and only appicable when using a hostname and is determined by looking at second level
* cron:
  * cron_name: any name will suffice, but must be unique when combined with cron_path, host, and user
  * cron_path: full path with any arguments; this would look exactly like a local cron
  * cron_min, cron_hour, cron_dom, cron_mon, cron_dow: representation of when cron should run; by default, values 
  will be *.  any integer or wildcard is supported: */<int>, where <int> >= 1
  * enabled: by default, any cron added will be set to 0 (off), so explicitly set to 1 when creating a new cron if you
  want it to run
  * host: provide the hostname for a host defined in system
  * user: provide the username for a user defined in auth
  * action: for multiple crons that have the same name, how should these be handled?
    * 0: attempt to run cron on systems in order they are provided, first success, return
    * 1: shuffle list of available systems, first success, return
    * 2: run cron on all systems at the same time
    * 3: if previous cron is still running during next cron interval, clobber and start new.  this is useful
    for long running crons

to run, add rcron.py to a cron or add it as a service to run every minute.  rcron will cache all cron data to 
self.cache_file (AES encrypted to ensure security of auth information) and use self.cache_file_temp when decrypting
and reading (will be deleted after).  rcron keeps track of which crons are running by writing 
/tmp/<sha256hash_of_cron_path_host_user_action>.rcron files in an attempt to keep multiple instances of the same
cron from running.  so, if you change any of those items for a cron between cron runs, it will be possible that any currently running cron will not be seen as "the same"; remember this if 
action=3 or it could result in multiple versions of the same cron running simultaneously.
