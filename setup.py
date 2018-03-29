#!/bin/env python
# $Id$
# $Date$
# setup.py
#
# Certify setup script

import os, sys, commands, argparse, re
from certify_config import *

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
	print "\n ### AIDE Setup ###\n";
	file = "certify_config.py"
	boundary = '### No boundary ###'

	print "## AIDE ##"
	if use_aide == 1:
		print "AIDE is currently enabled"
		print "By default AIDE is disabled"
		choice = raw_input("Disable AIDE [y/N]: ")
		if choice.upper() == 'Y':
			srcPattern = '^use_aide.*'
			targetPattern = "use_aide = 0"
			alterFile(file,'replace',srcPattern,targetPattern,boundary)
	else:
		print "AIDE is currently disabled (default)"
		choice = raw_input("Enable AIDE [y/N]: ")
		if choice.upper() == 'Y':
			srcPattern = '^use_aide.*'
			targetPattern = "use_aide = 1"
			alterFile(file,'replace',srcPattern,targetPattern,boundary)


def clamavConfig():
	print "\n  #### ClamAV Setup ####\n"
	file = "certify_config.py"
	boundary = '### No boundary ###'
	set_dirs = 1
	
	print "## ClamAV ##"
	if enableClamav == 1:
		print "ClamAV is currently enabled"
		print "By default ClamAV is disabled"
		choice = raw_input("Disable ClamAV [y/N]: ")
		if choice.upper() == 'Y':
			srcPattern = '^enableClamav.*'
			targetPattern = "enableClamav = 0"
			alterFile(file,'replace',srcPattern,targetPattern,boundary)
			set_dirs = 0
	else:
		print "ClamAV is currently disabled (default)"
		choice = raw_input("Enable ClamAV [y/N]: ")
		if choice.upper() == 'Y':
			srcPattern = '^enableClamav.*'
			targetPattern = "enableClamav = 1"
			alterFile(file,'replace',srcPattern,targetPattern,boundary)
			set_dirs = 1

	print "\n## Freshclam ##"
	if enableFreshclam == 1:
		print "Freshclam is enabled"
		print "By default Freshclam is disabled"
		choice = raw_input("Disable Freshclam [y/N]: ")
		if choice.upper() == 'Y':
			srcPattern = '^enableFreshclam.*'
			targetPattern = "enableFreshclam = 0"
			alterFile(file,'replace',srcPattern,targetPattern,boundary)
	else:
		print "Freshclam is currently disabled (default)"
		print "If this host can get updates from the internet you may want to enable Freshclam"
		choice = raw_input("Enable Freshclam [y/N]: ")
		if choice.upper() == 'Y':
			srcPattern = '^enableFreshclam.*'
			targetPattern = "enableFreshclam = 1"
			alterFile(file,'replace',srcPattern,targetPattern,boundary)

	print "\n## ClamAV Server ##"
	if clamavServer == 1:
		print "ClamAV Server is enabled"
		print "By default ClamAV Server is disabled"
		choice = raw_input("Disable ClamAV Server [y/N]: ")
		if choice.upper() == 'Y':
			srcPattern = '^clamavServer.*'
			targetPattern = "clamavServer = 0"
			alterFile(file,'replace',srcPattern,targetPattern,boundary)
	else:
		print "ClamAV Server is currently disabled (default)"
		print "If this host is an HTTP server configured to provide virus signatures to ClamAV clients,"
		print "you may want to enable ClamAV Server"
		choice = raw_input("Enable ClamAV Server [y/N]: ")
		if choice.upper() == 'Y':
			srcPattern = '^clamavServer.*'
			targetPattern = "clamavServer = 1"
			alterFile(file,'replace',srcPattern,targetPattern,boundary)

	if set_dirs == 1:
		print "\n## Directories to scan ##"
		print "By default these directories are scanned:"
		print "/bin /boot /etc /home /lib /lib64 /opt /root /sbin /usr /var"
		print "Current configuration::"
		print clamscanDirs
		choice = raw_input("Do you want to make a change [y/N]: ")
		if choice.upper() == 'Y':
			choice = raw_input("List directories to scan: ")
			srcPattern = '^clamscanDirs.*'
			targetPattern = 'clamscanDirs = "' + choice + '"'
			alterFile(file,'replace',srcPattern,targetPattern,boundary)
	

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
