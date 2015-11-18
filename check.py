#!/bin/env python
# check.py
# $Id$
# $Date$
# System security plan certification scripts

import argparse
import commands, subprocess, time, string, sys
import random , crypt , os, pwd, stat, grp
import paramiko, getpass, pexpect, re
from os.path import join, getsize
from certify_config import *
debug = 0

# change to certify directory 
filepath = sys.argv[0]
if '/' in filepath:
	certdir = os.path.dirname(filepath)
	os.chdir(certdir)

# Parse command line arguments
parser = argparse.ArgumentParser(
	description='If no arguments, all security tests will be performed',
	formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-i', '--interactive', action='store_true', help='interactive mode')
parser.add_argument('-c', '--check', action='store_true', help='md5 check')
parser.add_argument('-l', '--log', action='store_true', help='create log')
parser.add_argument('--logfile', default=logfile, help='log file name')
args = parser.parse_args()

# collect host information
date = commands.getoutput('date')
host = commands.getoutput('uname -n')
OS = commands.getoutput('uname -s')
release = commands.getoutput('uname -r')
release = oschk(OS,release)

tests = { 'Check Baseline MD5 files':'checkMD5',
	'Look for NULL passwords':'checkNull',
	'Check password rules':'checkPWrules',
	'Look for non-unique UIDs':'checkUID',
	'Look for shared accounts':'checkSharedAccnts',
	'Look for world writable files':'checkWorldWritable',
	'Look for unowned files':'checkUnowned',
	'Check authentication & auditing':'checkAuthentication',
	'Look for privileged users':'checkPrivUsers',
	'Check log file perms':'checkLogPerms',
	'Check enabled services':'checkServices',
	'Check USB storage access status':'checkUSB' }

testNo = {}
subNo = {}
n = 1
subprocess.call(['chmod', '640', args.logfile])

for item in sorted(tests):
	testNo[n] = item
	subNo[n] = tests[item]
	n += 1

def prntMenu():
	print("\nCheck menu")
	for item in testNo:
		s = repr(item).rjust(6) + ': ' + testNo[item] 
		print s

def pr(parg):
	parg.rstrip('\n')
	if args.interactive:
		if re.match(r'^#\s', parg):
			s = time.strftime("%b %d %H:%M:%S")
			s = s + " " + host + " check.py:\n" + parg
			print s
		elif re.match(r'^Good bye!', parg):
			print parg
		else:
			parg = '    ' + parg
			parg = re.sub(r'\n', '\n    ', parg)
			print parg + "\n"
	if args.log:
		try:
			f = open(logfile, 'a')
			if re.match(r'^#\s', parg):
				s = time.strftime("%b %d %H:%M:%S")
				s = s + " " + host + " check.py:\n" + parg + "\n"
				f.write(s)
			elif re.match(r'^Good bye!', parg):
				f.write(parg)
			else:
				parg = '    ' + parg
				parg = re.sub(r'\n', '\n    ', parg)
				f.write(parg + "\n")
			f.close()
		except IOError:
			print "Unable to open log file"
			sys.exit(2)

def checkMD5():
	md5file = "md5sums.txt"
	status = 'unchanged'
	pr("# Check Baseline MD5 files")
	pr("Running MD5SUMS test on " + md5file)
	try:
		f = open(md5file, 'r') 
		for line in f:
			words = line.split()
			if words[0] == host:
				ans, err = subprocess.Popen(["md5sum", words[3]], stdout=subprocess.PIPE).communicate()
				md5, fname = ans.split()
				if md5 != words[2]:
					msg = "Warning, " + words[3] + " has changed since last validation"
					pr(msg)
					status = "changed"
		f.close()
		if status == "unchanged":
			pr("Great, all files are unchanged")
	except IOError:
		print "Error: No md5sums.txt file, did you harden the system first?"
		sys.exit(2)

def checkNull():
	pr("# Look for NULL passwords")
	pr("Checking passwd entries")
	ans = commands.getstatusoutput("""awk -F: '{if($2=="")print}' /etc/passwd""")
	pr(ans[1])
	pr("Checking shadow entries")
	ans = commands.getstatusoutput("""awk -F: '{if($2=="")print}' /etc/shadow""")
	pr(ans[1])
	pr("If any accounts printed, the test failed")

def checkUID():
	pr("# Look for non-unique UIDs")
	file = "/etc/passwd"
	found = 0
	for line in open(file):
		words = line.split(':')
		for line2 in open(file):
			words2 = line2.split(':')
			if words[2] == words2[2] and words[0] != words2[0]:
				pr(words[0] + " and " + words2[0] + " have the same UID")
				found = 1
	if not found:
		pr("No duplicate UIDs found")

def checkSharedAccnts():
	pr("# Look for shared accounts")
	pr("The following is a list of possible shared acounts")
	file = "/etc/passwd"
	for line in open(file):
		line = line.rstrip('\n')
		words = line.split(':')
		if int(words[2]) >= 500 and words[6] != '/sbin/nologin':
			pr(line)

def checkClasses():
	classes = ''
	if use_cracklib:
		if int(cracklib['minclass']) == 4:
			classes = 'ludo'
		else:
			if int(cracklib['lcredit']) == -1:
				classes = classes + 'l'
			if int(cracklib['ucredit']) == -1:
				classes = classes + 'u'
			if int(cracklib['dcredit']) == -1:
				classes = classes + 'd'
			if int(cracklib['ocredit']) == -1:
				classes = classes + 'o'
			if not classes:
				classes = 'l'
	else:
			classes = 'ludo'

	return classes

def passgen(length, classes):
	chars = string.ascii_lowercase
	caps = string.ascii_uppercase
	nums = string.digits
	specials = ['@','#','$','&','!','<','>','[',']']
	cnt = lcnt = ucnt = dcnt = ocnt = 0
	pw = ''
	if use_cracklib:
		while cnt < length:
			if classes.find('l') >= 0 and cnt < length:
				if int(cracklib['lcredit']) == 0 or int(cracklib['lcredit']) == -1:
					pw = pw + random.choice(chars) 
					cnt = cnt + 1
				if int(cracklib['lcredit']) > 0 and lcnt < int(cracklib['lcredit']):
					lcnt = lcnt + 1
					length = length - 1
					if cnt < length:
						pw = pw + random.choice(chars) 
						cnt = cnt + 1
			if classes.find('u') >= 0 and cnt < length:
				if int(cracklib['ucredit']) == 0 or int(cracklib['ucredit']) == -1:
					pw = pw + random.choice(caps) 
					cnt = cnt + 1
				if int(cracklib['ucredit']) > 0 and ucnt < int(cracklib['ucredit']):
					ucnt = ucnt + 1
					length = length - 1
					if cnt < length:
						pw = pw + random.choice(caps) 
						cnt = cnt + 1
			if classes.find('d') >= 0 and cnt < length:
				if int(cracklib['dcredit']) == 0 or int(cracklib['dcredit']) == -1:
					pw = pw + random.choice(nums) 
					cnt = cnt + 1
				if int(cracklib['dcredit']) > 0 and dcnt < int(cracklib['dcredit']):
					dcnt = dcnt + 1
					length = length - 1
					if cnt < length:
						pw = pw + random.choice(nums) 
						cnt = cnt + 1
			if classes.find('o') >= 0 and cnt < length:
				if int(cracklib['ocredit']) == 0 or int(cracklib['ocredit']) == -1:
					pw = pw + random.choice(specials) 
					cnt = cnt + 1
				if int(cracklib['ocredit']) > 0 and ocnt < int(cracklib['ocredit']):
					ocnt = ocnt + 1
					length = length - 1
					if cnt < length:
						pw = pw + random.choice(specials) 
						cnt = cnt + 1

	elif use_passwdqc:
		while cnt < length:
			if classes.find('l') >= 0 and cnt < length:
				pw = pw + random.choice(chars) 
				cnt = cnt + 1
			if classes.find('u') >= 0 and cnt < length:
				pw = pw + random.choice(caps) 
				cnt = cnt + 1
			if classes.find('d') >= 0 and cnt < length:
				pw = pw + random.choice(nums) 
				cnt = cnt + 1
			if classes.find('o') >= 0 and cnt < length:
				pw = pw + random.choice(specials) 
				cnt = cnt + 1

	else:
		pr("No password strength rules. Enable cracklib or passwdqc")
		sys.exit(0)

	return pw, length

def createUserAccnt(username,uname):
	ans, err = subprocess.Popen(["getent", "passwd", uname], stdout=subprocess.PIPE).communicate()
	if not ans:
		subprocess.call(['/usr/sbin/useradd', '-c', username, uname])
	else:
		pr(uname + " exists")

def assignPassword(user, pw):
	child = pexpect.spawn ("passwd %s" % user)
	for x in xrange(5):
		i = child.expect ([
			"New .*password:",
			"Enter new password:",
			"Re-?type .*password:",
			"Try again",
			"all authentication tokens updated successfully"]
		)
		if i==0: # New .*password
			for line in child.before.splitlines():
				line = line.replace('\r\n','')
				if not re.match(r'^\s*$', line):
					if debug: pr(line)
			for line in child.after.splitlines():
				line = line.replace('\r\n','')
				if not re.match(r'^\s*$', line):
					if debug: pr(line)
			child.sendline(pw)
		elif i==1: # Enter new password:
			if debug: pr(child.before)
			if debug: pr(child.after)
			child.sendline(pw)
		elif i==2: # Re-?type .*password:
			if debug: pr(child.after)
			child.sendline(pw)
		elif i==3: # Try again
			if debug: pr(child.after)
			child.sendline(pw)
		elif i==4: # passwd: all authentication tokens updated successfully.
			if debug: pr(child.after)
			break
		else:
			if debug: pr("Unknown expect value")
			if debug: pr(child.before)
			if debug: pr(child.after)
			break

def removeUserAccnt(uname):
	ans, err = subprocess.Popen(["getent", "passwd", uname], stdout=subprocess.PIPE).communicate()
	if ans:
		subprocess.call(['userdel', '-rf', uname])
	else:
		pr(uname + " does not exist")
	
def checkWorldWritable():
	pr("# Look for world writeable files")
	ans = commands.getoutput('find / \( -path "/proc" -o -path "/rdbu" -o -path "/rdiff" -o -path "/home" -o -path "/cgroup" -o -path "/var/www/svn" -o -path "/selinux" \) -prune -o -type f -perm /o=w 2>&1 | egrep -v "Permission denied|/proc|/rdbu|/home|/rdiff|/cgroup|/var/www/svn|/selinux"')
	pr("# World writeable file search results")
	pr(ans)

def runSSH(host,user,password,command):
	try:
		client = paramiko.SSHClient()
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		pr("ssh " + host + " " + command)
		client.connect(host,username=user,password=password, look_for_keys=False)
		stdin, stdout, stderr = client.exec_command(command)
		data = stdout.readlines()
		for line in data:
			pr(line)
	except paramiko.AuthenticationException, e:
		pr("Authentication failed")

def setMinDays():
	pr("Temporarally changing PASS_MIN_DAYS to 0")
	file = "/etc/login.defs"
	save = "/etc/login.defs.last"
	temp = "/var/tmp/check.tmp"
	os.system("cp %s %s" % (file, save))
	f = open(file, "r")
	f2 = open(temp, "w")
	srcPattern = '^PASS_MIN_DAYS.*'
	targetPattern = 'PASS_MIN_DAYS 0'
	expr = re.compile(srcPattern)
	for line in f:
		result = expr.match(line)
		if result:
			result = re.sub(srcPattern, targetPattern,line,count=1)
			f2.write(result)
		elif not result:
			f2.write(line)
	f.close()
	f2.close()
	os.system("cp %s %s" % (temp, file))

def checkPWrules():
	pr("# Check password rules")
	pr("Checking login.defs file:")
	# file
	file = "/etc/login.defs"
	f = open(file)
	for line in f:
		line = line.rstrip('\n')
		if re.match("^PASS", line):
			pr(line)
		if re.match("^ENCRYPT_METHOD", line):
			pr(line)
		if re.match("^PASS_MIN_DAYS\s+[1-9]", line):
			setMinDays()
	f.close()
	
	pr("PAM passwd stack config:")
	# file
	file = "/etc/pam.d/passwd"
	msg = file + ":"
	pr(msg)
	for line in open(file):
		line = line.rstrip('\n')
		if re.match("^password", line):
			pr(line)
			if re.search("\s+substack\s+", line):
				words = line.split()
				subfile = "/etc/pam.d/" + words[2] 
				msg = subfile + ":"
				pr(msg)
				for line in open(subfile):
					line = line.rstrip('\n')
					if re.match("^password", line):
						pr(line)

	pr("Calculating password class requirments")
	classes = ''
	if use_cracklib:
		PASS_MIN_LEN = cracklib['minlen']
		classes = checkClasses()

	# Create test account
	pr("Creating sectester account")
	createUserAccnt('test account','sectester')
	password, length = passgen(int(PASS_MIN_LEN),classes)
	oldpw = password
	if debug: pr("Set sectester password")
	assignPassword('sectester', password)

	pr("Test acceptable length password with all required classes")
	newpw, length = passgen(int(PASS_MIN_LEN),classes)
	s = "password: " + newpw + ", length: " + str(length) + ", classes: " + classes
	pr(s)
	args = ('./testPassword.py', '-u', 'sectester','-o',oldpw,'-n',newpw)
	ret, err = subprocess.Popen(args, stdout=subprocess.PIPE).communicate()
	for line in ret.splitlines():
		line = line.replace('\r\n','')
		if not re.match(r'^\s*$', line):
			pr(line)
	if debug: pr("As root, reset password to original password")
	assignPassword('sectester', oldpw)

	# Short password attempt
	pr("Test short password with all required classes")
	newpw, length = passgen(int(PASS_MIN_LEN) - 1,classes)
	s = "password: " + newpw + ", length: " + str(length) + ", classes: " + classes
	pr(s)
	args = ('./testPassword.py', '-u', 'sectester','-o',oldpw,'-n',newpw)
	ret, err = subprocess.Popen(args, stdout=subprocess.PIPE).communicate()
	for line in ret.splitlines():
		line = line.replace(r'\r\n','')
		if not re.match(r'^\s*$', line):
			pr(line)
	if debug: pr("As root, reset password to original password")
	assignPassword('sectester', oldpw)

	# Missing uppercase
	if 'u' in classes or int(cracklib['ucredit']) == -1:
		pr("Test acceptable length password without uppercase charachters")
		if int(cracklib['ucredit']) == -1:
			pr("At least one uppercase charachter required\n")
		newpw, length = passgen(int(PASS_MIN_LEN),'ldo')
		s = "password: " + newpw + ", length: " + str(length) + ", classes: ldo"
		args = ('./testPassword.py', '-u', 'sectester','-o',oldpw,'-n',newpw)
		ret, err = subprocess.Popen(args, stdout=subprocess.PIPE).communicate()
		for line in ret.splitlines():
			line = line.replace(r'\r\n','')
			if not re.match(r'^\s*$', line):
				pr(line)
		if debug: pr("As root, reset password to original password")
		assignPassword('sectester', oldpw)

	# Missing digit
	if 'd' in classes or int(cracklib['dcredit']) == -1:
		pr("Test acceptable length password without digits")
		if int(cracklib['dcredit']) == -1:
			pr("At least one digit required\n")
		newpw, length = passgen(int(PASS_MIN_LEN),'luo')
		s = "password: " + newpw + ", length: " + str(length) + ", classes: luo"
		pr(s)
		args = ('./testPassword.py', '-u', 'sectester','-o',oldpw,'-n',newpw)
		ret, err = subprocess.Popen(args, stdout=subprocess.PIPE).communicate()
		for line in ret.splitlines():
			line = line.replace(r'\r\n','')
			if not re.match(r'^\s*$', line):
				pr(line)
		if debug: pr("As root, reset password to original password")
		assignPassword('sectester', oldpw)

	# Missing other
	if 'o' in classes or int(cracklib['ocredit']) == -1:
		pr("Test acceptable length password without special charachters")
		if int(cracklib['ocredit']) == -1:
			pr("At least one special charachter required\n")
		newpw, length = passgen(int(PASS_MIN_LEN),'lud')
		s = "password: " + newpw + ", length: " + str(length) + ", classes: lud"
		pr(s)
		args = ('./testPassword.py', '-u', 'sectester','-o',oldpw,'-n',newpw)
		ret, err = subprocess.Popen(args, stdout=subprocess.PIPE).communicate()
		for line in ret.splitlines():
			line = line.replace(r'\r\n','')
			if not re.match(r'^\s*$', line):
				pr(line)
		if debug: pr("As root, reset password to original password")
		assignPassword('sectester', oldpw)

	removeUserAccnt('sectester')
	file = "/etc/login.defs"
	save = "/etc/login.defs.last"
	try:
		open(save, 'r')
		os.system("cp %s %s" % (save, file))
		os.system("rm %s" % (save))
	except IOError:
		pass

def checkAuthentication():
	pr("# Check authentication & auditing")
	pr("Creating sectester account")
	createUserAccnt('test account','sectester')
	uid = pwd.getpwnam('sectester')[2]
	classes = checkClasses()
	password, length = passgen(int(logindefs['PASS_MIN_LEN']), classes)
	pr("Set sectester password")
	assignPassword('sectester', password)

	# Correct password attempt
	pr("Correct password attempt")
	s = "password: " + password + "  classes: " + classes
	pr(s)
	runSSH('localhost','sectester',password,'id')

	# Null password attempt
	pr("Null password attempt")
	runSSH('localhost','sectester',"",'id')

	# Test failed attempt account locking
	if use_pamtally:
		attemp = 0
		while attemp < int(pam_tally['deny']):
			attemp = attemp + 1
			runSSH('localhost','sectester',"xxxxx",'id')
			s = "Bad password attempt number " + str(attemp)
			pr(s)

		# Check for locked account
		ans, err = subprocess.Popen(["pam_tally2", "--user", "sectester", "-r"], stdout=subprocess.PIPE).communicate()
		pr(ans)
	else:
		pr('If failed login attempt account locking is desired, enable pam_tally')

	removeUserAccnt('sectester')

def checkUnowned():
	pr("# Searching for unowned files")
	ans = commands.getoutput('find / \( -path "/proc" -o -path "/rdbu" -o -path "/rdiff" \) -prune -o -nouser -print')
	pr("# Unowned file search results")
	pr(ans)

def checkPrivUsers():
	pr("# Look for privileged users")
	file = "/etc/passwd"
	chk = 0
	for line in open(file):
		line.rstrip('\n')
		words = line.split(':')
		if int(words[2]) == 0 and words[0] != 'root':
			pr(line)
			chk = 1
	if chk:
		pr("Verify listed privileged users")
	else:
		pr("No extra privileged accounts to check")
	
	pr("Look for sudo privileges")
	file = "/etc/sudoers"
	chk = 0
	for line in open(file):
		if not (re.match('^#', line) or re.match('^$', line) or re.match('Defaults', line)):
			if not re.match('^root', line):
				pr(line.rstrip('\n'))
				chk = 1
	if chk:
		pr("Verify listed sudo privileges")
	else:
		pr("No sudo privileges to verify")

def checkLogPerms():
	pr("# Check log file permissions")
	warn = 0
	for file in loglist:
		try:
			open(file)
			st = os.stat(file)
			uid = st.st_uid
			gid = st.st_gid
			if uid != 0 or gid != 0:
				pr("Warning: " + file + " should be owner root, group root")
				warn = 1
			
			ans = bool(st.st_mode & stat.S_IROTH)
			if ans:
				pr(file + " is world readable")
				warn = 1

			ans = bool(st.st_mode & stat.S_IWOTH)
			if ans:
				pr(file + " is world writeable")
				warn = 1

			ans = bool(st.st_mode & stat.S_IXOTH)
			if ans:
				pr(file + " is world executeable")
				warn = 1
		except IOError:
			continue
	
	if not warn:
		pr("Log file permissions are acceptable")

def checkServices():
	pr("# Check enabled services")
	# build list of all services
	allServices = []
	found = 0
	if release in ['fc15','fc16','fc17']:
		pr(release + " under construction")

	if release in sysvList: # sysv service management
		out, err = subprocess.Popen(["chkconfig", "--list", "--type", "sysv"], \
			stdout=subprocess.PIPE).communicate()

		for line in out.split('\n'):
			words = line.split()
			if len(words) > 1:
				if words[4] == '3:on' or words[6] == '5:on':
					allServices.append(words[0])

		for key in alwaysDisable:
			if key in allServices:
				pr("Warning, service " + key + " should be disabled")
				found = 1

	if release in systemdList: # systemd service management
		out, err = subprocess.Popen(["systemctl", "-t", "service", "list-unit-files"], \
			stdout=subprocess.PIPE).communicate()

		for line in out.split('\n'):
			if re.match(".*\s+enabled.*", line):
				words = line.split()
				allServices.append(words[0])

		for key in alwaysDisable:
			key = key + ".service"
			if key in allServices:
				pr("Warning, " + key + " should be disabled")
				found = 1

	if not found:
		pr("No unwanted services found")

def checkUSB():
	pr("# Check USB storage access status")
	file = "/etc/modprobe.d/harden_usb.conf"
	pr(file)
	try:
		f = open(file)
		s = '#install'
		found = f.read().count(s)
		if USB_STORAGE in ('y','Y','yes','Yes','YES'):
			if found >= 1:
				pr("USB storage enabled as specified")
			else:
				pr("Warning, USB storage should be enabled")
		elif USB_STORAGE in ('n','N','no','No','NO'):
			if found >= 1:
				pr("Warning, USB storage should not be enabled")
			else:
				pr("USB storage disabled as specified")
		else:
			pr("Invalid USB_STORAGE setting")
	except IOError:
		pr(file + " missing")

done = 0
while not done:
	if args.interactive:
		prntMenu()
		choice = raw_input("Enter choice or 'q' to quit [all]: ")
		if choice == 'q':
			done = 1
		elif choice == 'all':
			n = 1
			while n <= len(subNo):
				locals()[subNo[n]]()
				n = n + 1
		elif int(choice) >= len(subNo) + 1:
			pr("invalid choice " + choice)
		else:
			locals()[subNo[int(choice)]]()
	elif args.check:
			locals()[subNo[1]]()
			done = 1
	else:
		n = 1
		while n <= len(subNo):
			locals()[subNo[n]]()
			n = n + 1
		done = 1

pr('Good bye!')
