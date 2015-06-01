#!/bin/env python
# $Id: harden.py 566 2014-10-29 02:49:55Z rohare $
# $URL: file:///usr/local/svn/certify/trunk/harden.py $
# System security plan certification scripts

import argparse
import commands, os, re, errno, sys
import subprocess, time
from certify_config import *
debug = 0

# change to certify directory
filepath = sys.argv[0]
if '/' in filepath:
	certdir = os.path.dirname(filepath)
	os.chdir(certdir)

# Parse command line arguments
parser = argparse.ArgumentParser(
	description='If no arguments, all security options will be performed',
	formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-i', '--interactive', action='store_true', help='interactive mode')
parser.add_argument('-l', '--log', action='store_true', help='create log')
parser.add_argument('--logfile', default=logfile, help='log file name')
args = parser.parse_args()

# prevent concurrent execution
pid = commands.getoutput('echo $$')
lockfile = '/var/run/harden.lock'
if os.path.isfile(lockfile):
	print 'Found lockfile ' + lockfile + ", exiting" 
	os._exit(1)
else:
	lockfile = open(lockfile, 'w')
	lockfile.write(pid)
	lockfile.close()

# collect host information
date = commands.getoutput('date +%m/%d/%Y')
host = commands.getoutput('uname -n')
domainname = commands.getoutput('dnsdomainname')
OS = commands.getoutput('uname -s')
release = commands.getoutput('uname -r')
release = oschk(OS,release)

fixes = { 'Audit Config':'auditConfig',
	'Authentication Config':'authConfig',
	'Configure Banners':'issue',
	'Configure cron files':'cronfiles',
	'FTP setup':'ftpusers',
	'Manage Services':'serviceConfig',
	'Init Functions':'functions',
	'IP forwarding':'ipForward',
	'Log rotation':'logRotate',
	'Secure Login Defs':'loginDefs',
	'SSH':'sshd',
	'TCP wrappers':'wrappers',
	'USB storage':'usbStorage' }

fixNo = {}
subNo = {}
n = 1
for item in sorted(fixes):
	fixNo[n] = item
	subNo[n] = fixes[item]
	n += 1

def pr(parg):
	parg.rstrip('/n')
	if args.interactive:
		if re.match(r'^#\s', parg):
			s = time.strftime("%b %d %H:%M:%S")
			s = s + " " + host + " harden.py:\n" + parg
			print s
		elif re.match(r'^Good bye!', parg):
			print parg
		else:
			parg = '    ' + parg
			parg = re.sub(r'\n', '\n    ', parg)
			print parg

	if args.log:
		try:
			f = open(args.logfile, 'a')
			if re.match(r'^#\s', parg):
				s = time.strftime("%b %d %H:%M:%S")
				s = s + " " + host + " harden.py:\n" + parg + "\n"
				f.write(s)
			elif re.match(r'^Good bye!', parg):
				f.write(parg + "\n")
			else:
				parg = '    ' + parg
				parg = re.sub(r'\n', '\n    ', parg)
				f.write( parg + "\n")
			f.close()
		except IOError:
			print "Unable to open log file"
			sys.exit(2)

def prntMenu():
	print("\nHarden Menu")
	for item in fixNo:
		s = repr(item).rjust(6) + ': ' + fixNo[item]
		print s

def updateMD5(file):
	cmd = "/usr/bin/md5sum " + file
	md5sum = commands.getoutput(cmd)
	done = 0
	MD5 = open("md5sums.txt", 'a')
	MD5.close()
	MD5 = open("md5sums.txt", 'r')
	MD5new = open("temp", 'w')
	s = '^' + host + '.*' + file
	p = re.compile(s)
	for line in MD5: 
		m = p.search(line)
		if m:
			continue
		else:
			MD5new.write(line)

	MD5.close()
	s = host + "\t" + date + "\t" + md5sum + "\t" "\n"
	MD5new.write(s)
	MD5new.close()
	os.rename('temp', 'md5sums.txt')

def backup(file):
	if os.path.isfile(file):
		s = file + ".orig"
		if not os.path.isfile(s):
			os.system("cp %s %s" % (file, s))

		s = file + ".preharden"
		os.system("cp %s %s" % (file, s))
	else:
		s = "No file named: " + file
		pr(s)

def cryptChoice():
	if "el" in release:
		ret = commands.getoutput('authconfig | egrep -e "--passalgo"')
		if 'sha512' in ret:
			method = 'SHA512'
		elif 'sha256' in ret:
			method = 'SHA256'
		elif 'md5' in ret:
			method = 'MD5'
		else:
			method = 'CRYPT'
		return method
	else:
		return 'MD5'

def alterFile(file,action,srcPattern,targetPattern,boundary):
	"""alterFile - Add delete or modify portions of a file.

	keyword arguments:
	file           -- the name of the file to modify
	action         -- one of "replace", "delete", "before", "after"
	srcPattern     -- reference point for the change
	targetpattern  -- content of the change
	boundary       -- string delimiting the end of the search

	"""
	backup(file)
	f = open(file, "r")
	temp = "/var/tmp/harden." + pid
	f2 = open(temp, "w")

	expr = re.compile(srcPattern)
	boundary = re.compile(boundary)
	pastBoundary = 0
	cnt = 0

	if action == 'replace':
		for line in f:
			result = boundary.match(line)
			if result:
				pastBoundary = 1

			if pastBoundary:
				f2.write(line)
			else:
				result = expr.match(line)
				if result and cnt == 0:
					result = re.sub(srcPattern,targetPattern,line,count=1)
					f2.write(result)
					cnt = 1
				elif not result:
					f2.write(line)

	if action == 'delete':
		for line in f:
			result = boundary.match(line)
			if result:
				pastBoundary = 1

			if pastBoundary:
				f2.write(line)
			else:
				result = expr.match(line)
				if result:
					pass
				elif not result:
					f2.write(line)
			
	if action == 'before':
		for line in f:
			result = boundary.match(line)
			if result:
				pastBoundary = 1

			if pastBoundary:
				f2.write(line)
			else:
				result = expr.match(line)
				if result:
					f2.write(targetPattern + '\n')
					f2.write(line)
				elif not result:
					f2.write(line)
	
	if action == 'after':
		for line in f:
			result = boundary.match(line)
			if result:
				pastBoundary = 1

			if pastBoundary:
				f2.write(line)
			else:
				result = expr.match(line)
				if result:
					f2.write(line)
					f2.write(targetPattern)
				elif not result:
					f2.write(line)

	f.close()
	f2.close()
	os.system("cp %s %s" % (temp, file))
	os.system("rm %s" % (temp))

def pamCracklib():
	pr("# Cracklib config")
	# file
	file = '/etc/pam.d/system-auth'
	backup(file)
	pr(file)
	boundary = '### No boundary ###'
	# alterFile(file,action,srcPattern,targetPattern,boundary)
	
	# Remove existing cracklib entry
	srcPattern = '#?password\s+\w+\s+pam_cracklib.so.*'
	alterFile(file,'delete',srcPattern,'',boundary)

	# Remove existing passwdqc entry if it exists
	srcPattern = '#?password\s+\w+\s+pam_passwdqc.so.*'
	alterFile(file,'delete',srcPattern,'',boundary)

	# Insert new entry
	srcPattern = '#?password\s+\w+\s+pam_unix.so.*'
	s = 'password    requisite     pam_cracklib.so '
	if cracklib['try_first_pass'] and cracklib['try_first_pass'] <> '0':
		s = s + ' try_first_pass'
	if cracklib['retry'] and cracklib['retry'] <> '0':
		s = s + ' retry=' + cracklib['retry']
	if cracklib['difok'] and cracklib['difok'] <> '0':
		s = s + ' difok=' + cracklib['difok']
	if cracklib['minlen'] and cracklib['minlen'] <> 0:
		s = s + ' minlen=' + str(cracklib['minlen'])
	if cracklib['dcredit']:
		s = s + ' dcredit=' + cracklib['dcredit']
	if cracklib['ucredit']:
		s = s + ' ucredit=' + cracklib['ucredit']
	if cracklib['lcredit']:
		s = s + ' lcredit=' + cracklib['lcredit']
	if cracklib['ocredit']:
		s = s + ' ocredit=' + cracklib['ocredit']
	if cracklib['minclass'] and cracklib['minclass'] <> '0':
		s = s + ' minclass=' + cracklib['minclass']
	if cracklib['maxrepeat'] and cracklib['maxrepeat'] <> '0':
		s = s + ' maxrepeat=' + cracklib['maxrepeat']
	if cracklib['maxsequence'] and cracklib['maxsequence'] <> '0':
		s = s + ' maxsequence=' + cracklib['maxsequence']
	if cracklib['maxclassrepeat'] and cracklib['maxclassrepeat'] <> '0':
		s = s + ' maxclassrepeat=' + cracklib['maxclassrepeat']
	if cracklib['reject_username'] and cracklib['reject_username'] <> '0':
		s = s + ' reject_username'
	if cracklib['gecoscheck'] and cracklib['gecoscheck'] <> '0':
		s = s + ' gecoscheck'
	if cracklib['enforce_for_root'] and cracklib['enforce_for_root'] <> '0':
		s = s + ' enforce_for_root'
	if cracklib['use_authtok'] and cracklib['use_authtok'] <> '0':
		s = s + ' use_authtok'
	targetPattern = s + ' type='
	pr(targetPattern)
	alterFile(file,'before',srcPattern,targetPattern,boundary)
	updateMD5(file)

	if release in ['el6', 'el7']:
		# file
		file = '/etc/pam.d/password-auth'
		backup(file)
		pr(file)
		boundary = '### No boundary ###'
		# alterFile(file,action,srcPattern,targetPattern,boundary)
		
		# Remove existing cracklib entry
		srcPattern = '#?password\s+\w+\s+pam_cracklib.so.*'
		alterFile(file,'delete',srcPattern,'',boundary)

		# Remove existing passwdqc entry if it exists
		srcPattern = '#?password\s+\w+\s+pam_passwdqc.so.*'
		alterFile(file,'delete',srcPattern,'',boundary)

		# Insert new entry
		srcPattern = '#?password\s+\w+\s+pam_unix.so.*'
		alterFile(file,'before',srcPattern,targetPattern,boundary)
		pr(targetPattern)
		updateMD5(file)

def pamPasswdqc():
	pr("# pam_passwdqc config")
	boundary = '### No boundary ###'
	# alterFile(file,action,srcPattern,targetPattern,boundary)

	# file
	file = '/etc/pam.d/system-auth'
	pr(file)
	backup(file)

	# remove existing entry
	srcPattern = '#?password\s+\w+\s+pam_passwdqc.so.*'
	alterFile(file,'delete',srcPattern,'',boundary)

	# remove cracklib entry if it exists
	srcPattern = '#?password\s+\w+\s+pam_cracklib.so.*'
	alterFile(file,'delete',srcPattern,'',boundary)

	# insert new entry
	srcPattern = '#?password\s+\w+\s+pam_unix.*'
	targetPattern = 'password   required  pam_passwdqc.so ' + MIN
	pr(targetPattern)
	alterFile(file,'before',srcPattern,targetPattern,boundary)
	updateMD5(file)

def pamTally():
	pr("# pam_tally config")
	boundary = '### No boundary ###'

	if use_pamtally:
		tally_rules = 'pam_tally' + pam_tally['version'] + '.so'
		if pam_tally['deny'] and pam_tally['deny'] <> '0':
			tally_rules = tally_rules + ' deny=' + pam_tally['deny']

			if pam_tally['lock_time'] and pam_tally['lock_time'] <> '0':
				tally_rules = tally_rules + ' lock_time=' + pam_tally['lock_time']

			if pam_tally['unlock_time'] and pam_tally['unlock_time'] <> '0':
				tally_rules = tally_rules + ' unlock_time=' + pam_tally['unlock_time']
		
			if pam_tally['magic_root'] and pam_tally['magic_root'] <> '0':
				tally_rules = tally_rules + ' magic_root=' + pam_tally['magic_root']

			if pam_tally['even_deny_root'] and pam_tally['even_deny_root'] <> '0':
				tally_rules = tally_rules + ' even_deny_root=' + pam_tally['even_deny_root']

				if pam_tally['root_unlock_time'] and pam_tally['root_unlock_time'] <> '0':
					tally_rules = tally_rules + ' root_unlock_time=' + pam_tally['root_unlock_time']

		# alterFile(file,action,srcPattern,targetPattern,boundary)
		# file
		file = '/etc/pam.d/login'
		pr(file)
		backup(file)

		# remove existing entries
		srcPattern = '#?auth\s+\w+\s+pam_tally.*'
		alterFile(file,'delete',srcPattern,'',boundary)

		srcPattern = '#?account\s+\w+\s+pam_tally.*'
		alterFile(file,'delete',srcPattern,'',boundary)

		# insert new entrys
		srcPattern = '#?auth\s+\w+\s+system-auth.*'
		targetPattern = 'auth       required     ' + tally_rules
		pr(targetPattern)
		alterFile(file,'before',srcPattern,targetPattern,boundary)

		srcPattern = '#?account\s+\w+\s+system-auth.*'
		targetPattern = 'account    required     ' + 'pam_tally' + pam_tally['version'] + '.so'
		pr(targetPattern)
		alterFile(file,'before',srcPattern,targetPattern,boundary)
		updateMD5(file)

		# file
		file = '/etc/pam.d/sshd'
		pr(file)
		backup(file)

		# remove existing entries
		srcPattern = '#?auth\s+\w+\s+pam_tally.*'
		alterFile(file,'delete',srcPattern,'',boundary)

		srcPattern = '#?account\s+\w+\s+pam_tally.*'
		alterFile(file,'delete',srcPattern,'',boundary)

		# insert new entrys
		srcPattern = '#?auth\s+\w+\s+password-auth.*'
		targetPattern = "auth       required     " + tally_rules
		p = re.compile(srcPattern)
		FILE = open(file, 'r')
		for line in FILE:
			m = p.search(line)
			if m:
				pr(targetPattern)
				alterFile(file,'before',srcPattern,targetPattern,boundary)
		FILE.close()
		
		srcPattern = '#?auth\s+\w+\s+system-auth.*'
		targetPattern = 'auth       required     ' + tally_rules
		p = re.compile(srcPattern)
		FILE = open(file, 'r')
		for line in FILE:
			m = p.search(line)
			if m:
				pr(targetPattern)
				alterFile(file,'before',srcPattern,targetPattern,boundary)
		FILE.close()
		
		srcPattern = '#?account\s+\w+\s+password-auth.*'
		targetPattern = 'account    required     pam_tally' + pam_tally['version'] + '.so'
		p = re.compile(srcPattern)
		FILE = open(file, 'r')
		for line in FILE:
			m = p.search(line)
			if m:
				pr("  " + targetPattern)
				alterFile(file,'before',srcPattern,targetPattern,boundary)
		FILE.close()
		
		srcPattern = '#?account\s+\w+\s+system-auth.*'
		targetPattern = 'account    required     pam_tally' + pam_tally['version'] + '.so'
		p = re.compile(srcPattern)
		FILE = open(file, 'r')
		for line in FILE:
			m = p.search(line)
			if m:
				pr(targetPattern)
				alterFile(file,'before',srcPattern,targetPattern,boundary)
		FILE.close()
		updateMD5(file)

		# file
		file = '/etc/pam.d/system-auth'
		backup(file)

		# remove existing entries
		srcPattern = '#?auth\s+\w+\s+pam_tally.*'
		alterFile(file,'delete',srcPattern,'',boundary)

		srcPattern = '#?account\s+\w+\s+pam_tally.*'
		alterFile(file,'delete',srcPattern,'',boundary)
		updateMD5(file)
	else:
		# file
		file = '/etc/pam.d/login'
		pr(file)
		backup(file)

		# remove existing entries
		srcPattern = '#?auth\s+\w+\s+pam_tally.*'
		alterFile(file,'delete',srcPattern,'',boundary)

		srcPattern = '#?account\s+\w+\s+pam_tally.*'
		alterFile(file,'delete',srcPattern,'',boundary)
		
		# file
		file = '/etc/pam.d/sshd'
		pr(file)
		backup(file)

		# remove existing entries
		srcPattern = '#?auth\s+\w+\s+pam_tally.*'
		alterFile(file,'delete',srcPattern,'',boundary)

		srcPattern = '#?account\s+\w+\s+pam_tally.*'
		alterFile(file,'delete',srcPattern,'',boundary)

def passwordAge():
	pr('# Update minimum password age')
	# file
	file = "/etc/passwd"
	pr(file)
	Shells = open("/etc/shells").readlines()
	f = open(file, "r")
	for line in f:
		line = line.strip()
		words = line.split(':')
		Shell = words[6] + '\n'
		if int(words[2]) >= 500 and Shell in Shells and Shell != '/sbin/nologin\n':
			cmd = 'chage -M ' + str(logindefs['PASS_MAX_DAYS']) + " " + words[0]
			ans, err = subprocess.Popen(["getent", "shadow", words[0]], stdout=subprocess.PIPE).communicate()
			sfline = ans.strip()
			sfwords = sfline.split(':')
			if sfwords[1] == 'x' or sfwords[1] == '!':
				cmd = 'chage -M 99999' + " " + words[0]
			if not err:
				pr(cmd)
				ret = commands.getoutput(cmd)

def auditConfig():
	pr("# Configure auditd")
	# file
	file = "/etc/audit/auditd.conf"
	pr(file)
	backup(file)
	
	for key in audit_option:
		target = key + " = " + audit_option[key]
		pr(target)
		srcPattern = '#*(\s*)' + key + '\s.*'
		targetPattern = '\\1' + target
		boundary = '### No boundary ###'
		# alterFile(file,action,srcPattern,targetPattern,boundary)
		alterFile(file,'replace',srcPattern,targetPattern,boundary)
	updateMD5(file)

def authConfig():
	pr("# authConfig")
	pr("pam module configuration")
	backup("/etc/pam.d/system-auth")
	
	aclist = [ 'el6', 'el7' ]
	if release in aclist:
		s = 'authconfig --savebackup=harden_' + commands.getoutput('date +%y%m%d')
		ret = os.system(s)
	else:
		s = "--savebackup option not supported on " + str(release) + " authconfig"

	pr(s)
	cryptMethod = cryptChoice()
	file = "/etc/login.defs"
	boundary = '### No boundary ###'
	srcPattern = 'ENCRYPT_METHOD.*'
	targetPattern = 'ENCRYPT_METHOD ' + cryptMethod
	alterFile(file,'replace',srcPattern,targetPattern,boundary)

	if not use_passwdqc and not use_cracklib:
		pr("No password strength module selected")
		pr("Using default cracklib")
		pamCracklib()

	if use_passwdqc and use_cracklib:
		pr("Can't use passwdqc and cracklib concurrently")
		pr("Using default cracklib")
		pamCracklib()
	
	if use_cracklib and not use_passwdqc:
		pamCracklib()

	if use_passwdqc and not use_cracklib:
		pamPasswdqc()
	
	pamTally()
	passwordAge()

def issue():
	pr("# Banner config")
	dn = commands.getoutput('host '+ host)
	BANNER = BANNER_LLNL
	rx_home = re.search("ohares.us", dn)
	rx_llnl = re.search("llnl.gov", dn)

	if rx_home:
		BANNER = BANNER_OHARES
	elif rx_llnl:
		BANNER = BANNER_LLNL

	list = [ "/etc/issue", "/etc/issue.net" ]
	# file
	for file in list:
		if os.path.isfile(file):
			s = "Updating " + file
			pr(s)
			backup(file)
			f = open(file, "w")
			f.write(BANNER)
			f.close()
			updateMD5(file)

	# file
	file = '/etc/gconf/gconf.xml.mandatory/%gconf-tree.xml'
	if os.path.isfile(file):
		s = "Updating " + file
		pr(s)
		backup(file)
		f = open(file, "r")
		test = f.read()
		f.close()
		ret = re.sub(r"(<stringvalue>\n).*(\n\s+</stringvalue>)", \
			r'\g<1>'+BANNER+r'\g<2>', \
			test, re.MULTILINE)
		f = open(file, "w")
		f.write(ret)
		f.close()
		updateMD5(file)

def cronfiles():
	pr("# Hardening cron files")
	pr('chown root:root /etc/crontab')
	subprocess.call(["chown" , "root:root", "/etc/crontab"])

	pr('chmod 0400 /etc/crontab')
	subprocess.call(["chmod", "0400", "/etc/crontab"])

	pr('chown root:root /var/spool/cron')
	subprocess.call(["chown", "-R", "root:root", "/var/spool/cron"])

	pr('chmod -R go-rwx /var/spool/cron')
	subprocess.call(["chmod", "-R", "go-rwx", "/var/spool/cron"])

def ftpusers():
	pr("# Updating ftpusers")
	file = "/etc/ftpusers"
	pr(file)
	backup(file)
	f = open(file, "w")
	pw = open("/etc/passwd", "r")
	list = []
	for line in pw:
		line.strip()
		entry = line.split(':')
		if int(entry[2]) < 500:
			uid = entry[0]
			f.write(uid + "\n")
			pr(uid)
	pw.close()
	f.close()
	updateMD5(file)

def serviceConfig():
	pr("# List enabled services")
	DEVNULL = open(os.devnull, 'wb')
	# build list of all services
	allServices = [] 
	
	if release in systemdList:
		out, err = subprocess.Popen(["systemctl", "-t", "service", "list-unit-files"], \
			stdout=subprocess.PIPE).communicate()

		for line in out.split('\n'):
			if re.match(".*\s+enabled.*", line):
				words = line.split()
				allServices.append(words[0])
				print line

		for key in alwaysDisable:
			key = key + ".service"
			if key in allServices:
				pr("Disabling " + key)
				subprocess.call(["systemctl", "disable", key])

	if release in sysvList:
		out, err = subprocess.Popen(["chkconfig", "--list"], \
			stdout=subprocess.PIPE).communicate()

		for line in out.split('\n'):
			if line == '\n':
				continue
			elif re.match("^xinetd", line):
				continue
			elif not re.match("^\s+", line):
				words = line.split()
				if len(words) > 1:
					if words[4] == '3:on' or words[6] == '5:on':
						pr(line)
					allServices.append(words[0])
		
		for key in alwaysDisable:
			if key in allServices:
				pr("Disabling " + key)
				subprocess.call(["chkconfig" , key, "off"])
				subprocess.call(["service" , key, "stop"], \
					stdout=DEVNULL, stderr=DEVNULL)

	DEVNULL.close()
	pr("\n\tReview list and disable unwanted services")

def functions():
	pr("# Making function changes")
	# file
	file = "/etc/init.d/functions"
	pr(file)
	srcPattern = 'umask.*'
	targetPattern = 'umask 027'
	pr(targetPattern)
	boundary = '### No boundary ###'
	# alterFile(file,action,srcPattern,targetPattern,boundary)
	alterFile(file,'replace',srcPattern,targetPattern,boundary)
	updateMD5(file)

def ipForward():
	pr("# IP forward config")
	# file
	file = "/etc/sysctl.conf"
	srcPattern = 'net.ipv4.ip_forward.*'
	boundary = '### No boundary ###'
	if ipfwd in ['1','y','Y','yes','Yes']:
		pr("Enabling IP forwarding, you must manually configure iptables")
		targetPattern = 'net.ipv4.ip_forward = 1'
		pr(file + ": " + targetPattern)
		alterFile(file,'replace',srcPattern,targetPattern,boundary)

	if ipfwd in ['0','n','N','no','No']:
		pr("Disabling IP forwarding")
		targetPattern = 'net.ipv4.ip_forward = 0'
		pr(file + ": " + targetPattern)
		alterFile(file,'replace',srcPattern,targetPattern,boundary)
	else:
		pr("Disabling IP forwarding")
		targetPattern = 'net.ipv4.ip_forward = 0'
		pr(file + ": " + targetPattern)
		alterFile(file,'replace',srcPattern,targetPattern,boundary)
	updateMD5(file)

def logRotate():
	pr("# Modifying log rotation")
	# file
	file = "/etc/logrotate.conf"

	srcPattern = '^#\s+rotate log files.*'
	targetPattern = '# rotate log files ' + LOG_ROT_SCHED
	pr('rotate log files ' + LOG_ROT_SCHED)
	boundary = '### No boundary ###'
	alterFile(file,'replace',srcPattern,targetPattern,boundary)

	for key in ('daily','weekly','monthly'):
		srcPattern = '^' + key
		targetPattern = LOG_ROT_SCHED
		alterFile(file,'replace',srcPattern,targetPattern,boundary)
	
	srcPattern = '# keep.*worth of backlogs'
	targetPattern = '# keep ' + LOG_ROT_KEEP + ' ' + LOG_ROT_SCHED + ' logs'
	pr('keep ' + LOG_ROT_KEEP + ' ' + LOG_ROT_SCHED + ' logs')
	alterFile(file,'replace',srcPattern,targetPattern,boundary)
	updateMD5(file)

def loginDefs():
	pr("# Configuring login defaults")
	# file
	file = "/etc/login.defs"
	pr( file)
	srcPattern = '^PASS_MAX_DAYS.*'
	targetPattern = 'PASS_MAX_DAYS ' + str(logindefs['PASS_MAX_DAYS'])
	pr(targetPattern)
	boundary = '### No boundary ###'
	alterFile(file,'replace',srcPattern,targetPattern,boundary)

	srcPattern = '^PASS_MIN_DAYS.*'
	targetPattern = 'PASS_MIN_DAYS ' + logindefs['PASS_MIN_DAYS']
	pr(targetPattern)
	alterFile(file,'replace',srcPattern,targetPattern,boundary)

	srcPattern = '^PASS_MIN_LEN.*'
	targetPattern = 'PASS_MIN_LEN ' + str(logindefs['PASS_MIN_LEN'])
	pr(targetPattern)
	alterFile(file,'replace',srcPattern,targetPattern,boundary)

	srcPattern = '^MD5_CRYPT_ENAB.*'
	targetPattern = 'MD5_CRYPT_ENAB ' + logindefs['MD5_CRYPT_ENAB']
	pr(targetPattern)
	alterFile(file,'replace',srcPattern,targetPattern,boundary)

	srcPattern = '^UMASK.*'
	targetPattern = 'UMASK ' + logindefs['UMASK']
	pr(targetPattern)
	alterFile(file,'replace',srcPattern,targetPattern,boundary)
	updateMD5(file)

def sshd():
	pr("# SSH config")
	# file
	file = "/etc/ssh/sshd_config"
	pr(file)

	for key in sshd_option:
		target = key + " " + sshd_option[key]
		pr(target)
		srcPattern = '#*(\s*)' + key + '\s.*'
		targetPattern = '\\1' + target
		boundary = '\s*Match'
		alterFile(file,'replace',srcPattern,targetPattern,boundary)

	updateMD5(file)
	ret = commands.getoutput('service sshd restart')
	pr(ret)

hosts_allow_header = """#
# hosts.allow	This file contains access rules which are used to
#		allow or deny connections to network services that
#		either use the tcp_wrappers library or that have been
#		started through a tcp_wrappers-enabled xinetd.
#
#		See 'man 5 hosts_options' and 'man 5 hosts_access'
#		for information on rule syntax.
#		See 'man tcpd' for information on tcp_wrappers
#
"""

hosts_deny_header = """#
# hosts.deny	This file contains access rules which are used to
#		deny connections to network services that either use
#		the tcp_wrappers library or that have been
#		started through a tcp_wrappers-enabled xinetd.
#
#		The rules in this file can also be set up in
#		/etc/hosts.allow with a 'deny' option instead.
#
#		See 'man 5 hosts_options' and 'man 5 hosts_access'
#		for information on rule syntax.
#		See 'man tcpd' for information on tcp_wrappers
#
"""

def wrappers():
	pr("# tcpwrapper config")
	# file
	file = "/etc/hosts.allow"

	if os.path.isfile(file):
		# delete DENY entries
		pr("Remove DENY entries in " + file)
		boundary = '### No boundary ###'
		srcPattern = '^.*:\s*DENY\s*$'
		alterFile(file,'delete',srcPattern,'targetPattern',boundary)
		altered = 0
		for line in open(file, 'r'):
			if not line.startswith('#'):
				altered = 1

		if not altered:
			for entry in (hosts_allow):
				if not entry in open(file).read():
					f = open(file, 'a')
					f.write(entry + "\n")
					f.close()
	else:
		f = open(file, 'w')
		f.write(hosts_allow_header)
		for entry in (hosts_allow):
			f.write(entry + "\n")
		f.close()
	updateMD5(file)

	# file
	file = "/etc/hosts.deny"
	pr("Add deny all to end of " + file)

	if os.path.isfile(file):
		boundary = '### No boundary ###'
		srcPattern = '^.*:\s*DENY\s*$'
		alterFile(file,'delete',srcPattern,'targetPattern',boundary)
		altered = 0
		for line in open(file, 'r'):
			if not line.startswith('#'):
				altered = 1

		if not altered:
			for entry in (hosts_deny):
				srcPattern = '^ALL : ALL\s*$'
				if not entry in open(file).read():
					f = open(file, 'a')
					f.write(entry + "\n")
					pr(entry)
					f.close()
	else:
		f = open(file, 'w')
		f.write(hosts_deny_header)
		for entry in (hosts_deny):
			f.write(entry + "\n")
			pr(entry)
		f.close()
	updateMD5(file)

def usbStorage():
	pr("# USB Storage Config")
	file = "/etc/modprobe.d/harden_usb.conf"
	pr(file)
	f = open(file, 'w')
	if USB_STORAGE in ('y','Y','yes','Yes'):
		f.write('#install usb-storage :\n')
		pr('Inabling usb-storage')
		pr('#install usb-storage :')
		subprocess.call(["modprobe", "usb_storage"])
	else:
		f.write('install usb-storage :\n')
		pr('Disabling usb-storage')
		pr('install usb-storage :')
		subprocess.call(["rmmod", "usb_storage"])

	f.close()
	subprocess.call(["chmod" , "0644", file])
	updateMD5(file)

done = 0
while not done:
	choice = ''
	if args.interactive:
		prntMenu()
		choice = raw_input("Enter choice or 'q' to quit [all]: ")
	else:
		choice = 'all'
		done = 1

	if choice == 'q':
		done = 1
	elif choice == 'all':
		if args.interactive != 1:
			pr("Running all")
			i = 1
			while i <= len(fixes):
				locals()[subNo[i]]()
				i += 1

	elif int(choice) >= len(fixes) + 1:
		print "invalid choice ", choice
	else:
		locals()[subNo[int(choice)]]()

os.remove("/var/run/harden.lock")
pr('Good bye!')

