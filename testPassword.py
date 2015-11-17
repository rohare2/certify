#!/usr/bin/env python
# $Id$
# $Date: Thu Sep 3 08:40:55 2015 -0700$

import os
import sys
import pexpect
import getopt
import pwd
debug = 0

def main(argv):
	user = ''
	oldpw = ''
	newpw = ''
	try:
		opts, args = getopt.getopt(argv, "hu:o:n:",["user=","oldwpw=","newpw"])
	except getopt.GetoptError:
		print 'testPasswd.py -u <user> -o <oldpw> -n <newpw>'
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print 'testPasswd.py -u <user> -o <oldpw> -n <newpw>'
			sys.exit()
		elif opt in ("-u", "--user"):
			user = arg
		elif opt in ("-o", "--oldpw"):
			oldpw = arg
		elif opt in ("-n", "--newpw"):
			newpw = arg
	
	if not user:
		print "Must provide an user name"
		sys.exit(2)
	if not oldpw:
		print "Must provide an old password"
		sys.exit(2)
	if not newpw:
		print "Must provide a new password"
		sys.exit(2)

	uid = pwd.getpwnam(user)[2]
	os.setuid(uid)
	if os.getuid() == 0:
		print "Must be run as non-root user"
		sys.exit(2)

	child = pexpect.spawn ("passwd")
	for x in xrange(10):
		i = child.expect ([
			"New .*password:",
			"Enter new password:",
			"Re-?type .*password:",
			"Try again",
			"\(current\).*password:",
			"passwd: all authentication tokens updated successfully.",
			"passwd: Authentication token manipulation error",
			"You must wait longer to change your password",
			"passwd: Have exhausted maximum number of retries for service",
			"Password:"]
		)
		if i==0: # New .*password
			if debug: print "i = " + str(i)
			print child.before
			print child.after
			child.sendline(newpw)
		elif i==1: # Enter new password:
			if debug: print "i = " + str(i)
			print child.before
			print child.after
			child.sendline(newpw)
		elif i==2: # Re-?type .*password:
			if debug: print "i = " + str(i)
			print child.after
			child.sendline(newpw)
		elif i==3: # Try again
			if debug: print "i = " + str(i)
			print child.after
			child.sendline(newpw)
			break
		elif i==4: # (current).*password
			if debug: print "i = " + str(i)
			print child.before 
			print child.after 
			child.sendline(oldpw)
		elif i==5: # passwd: all authentication tokens updated successfully.
			if debug: print "i = " + str(i)
			print child.after 
			break
		elif i==6: # passwd: Authentication token manipulation error
			if debug: print "i = " + str(i)
			print child.after 
			break
		elif i==7: # You must wait longer to change your password
			if debug: print "i = " + str(i)
			print child.after 
			break
		elif i==8: # passwd: Have exhausted maximum number of retries for service
			if debug: print "i = " + str(i)
			print child.after 
			break
		elif i==9: # Password:
			if debug: print "i = " + str(i)
			print child.after 
			break
		else:
			if debug: print "i = " + str(i)
			print "Unknown expect value"
			print child.before
			print child.after
			break

if __name__ == "__main__":
	main(sys.argv[1:])
