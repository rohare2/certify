#!/bin/env python
# $Id$
# $Date$
# setup.py
#
# Certify setup script

import os, sys, commands, argparse, re

# prevent concurrent execution
pid = commands.getoutput('echo $$')
lockfile = '/var/run/certify_setup.lock'
if os.path.isfile(lockfile):
	print 'Found lockfile ' + lockfile + ", exiting"
else:
	lockfile = open(lockfile, 'w')
	lockfile.write(pid)
	lockfile.close()

try:
	f_in = open("certify_config.py", 'r')
except:
	print "Unable to open configuration file"
	sys.exit(2)

fixes = {'AIDE':'aideConfig',
	'ClamAV':'clamavConfig'}

fixNo = {}
subNo = {}
n = 1
for item in sorted(fixes):
	fixNo[n] = item
	subNo[n] = fixes[item]
	n += 1


def prntMenu():
	print("\nCertify Setup")
	for item in fixNo:
		s = repr(item).rjust(6) + ': ' + fixNo[item]
		print s


def alterFile(file,action,srcPattern,targetPattern,boundary):
	"""alterFile - Add delete or modify portions of a file.

	keyword arguments:
	file           -- the name of the file to modify
	action         -- one of "replace", "delete", "before", "after"
	srcPattern     -- reference point for the change
	targetpattern  -- content of the change
	boundary       -- string delimiting the end of the search

	"""
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

def aideConfig():
	print "in aideConfig\n";


def clamavConfig():
	print "\n  #### ClamAV Setup ####\n"
	file = "certify_config.py"
	boundary = '### No boundary ###'
	
	choice = raw_input("Enable ClamAV [Y]: ")
	if choice == '':
		choice = 'Y'
	print "enableClamav: " + choice + "\n"
	srcPattern = '^enableClamav.*'
	if choice == 'Y':
		targetPattern = "enableClamav = 1"
	else:
		targetPattern = "enableClamav = 0"
	alterFile(file,'replace',srcPattern,targetPattern,boundary)


	choice = raw_input("User Freshclam [Y]: ")
	if choice == '':
		choice = 'Y'
	print "enableFreshclam: " + choice + "\n"

	choice = raw_input("Virus signature server [N]: ")
	if choice == '':
		choice = 'N'
	print "clamavServer: " + choice + "\n"

	choice = raw_input("Directories to scan [/bin /boot /etc /home /lib /lib64 /opt /root /sbin /usr /var]: ")
	if choice == '':
		choice = "/bin /boot /etc /home /lib /lib64 /opt /root /sbin /usr /var"
	print "clamscanDirs: " + choice + "\n"
	

done = 0
while not done:
	choice = ''
	prntMenu()
	choice = raw_input("Enter choice or 'q' to quit: ")

	if choice == 'q':
		done = 1
	elif int(choice) >= len(fixes) + 1:
		print "invalid choice ", choice
	else:
		locals()[subNo[int(choice)]]()


os.remove("/var/run/certify_setup.lock")
print "Good bye!"
