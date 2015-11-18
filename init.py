#! /bin/env python 
# $Id$
# $Date$
# RPM scriptlet for initializing the configuration database

import commands, subprocess, os, sys, re
import sqlite3

# initialize dababase
dbfile = '/usr/local/certify/certify.db'
if os.path.isfile(dbfile):
	print "nothing to do, dbfile already exists"
	exit()

print "initializing sqlite database"
try:
	conn = sqlite3.connect(dbfile)
except:
	print "Could not create sqlite database"
	exit()


# Create services table
c = conn.cursor()
c.execute('''CREATE TABLE services (service, state, type)''')

# Determine os release
OS = commands.getoutput('uname -s')
release = commands.getoutput('uname -r')
if 'el5' in release:
	release = 'el5'
elif 'el6' in release:
	release = 'el6'
elif 'el7' in release:
	release = 'el7'

if release in ['el5', 'el6']:
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
				# add db record
				if words[4] == '3:on' or words[6] == '5:on':
					c.execute("INSERT INTO services VALUES (?, ?, ?)", (words[0], 'on', 'sysv'))
				elif words[4] == '3:off' or words[6] == '5:off':
					c.execute("INSERT INTO services VALUES (?, ?, ?)", (words[0], 'off', 'sysv'))
		else:
			words = line.split()
			if words[1] == 'on':
				c.execute("INSERT INTO services VALUES (?, ?, ?)", (words[0], 'on', 'xinet'))
			if words[1] == 'off':
				c.execute("INSERT INTO services VALUES (?, ?, ?)", (words[0], 'off', 'xinet'))


conn.commit()
conn.close()

