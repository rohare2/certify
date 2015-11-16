#! /bin/env python 
# $Id$
# $Date: Thu Sep 3 08:40:55 2015 -0700$
# Tool for configuring certify controls

import argparse
import subprocess, os, sys
import sqlite3

filepath = sys.argv[0]
if '/' in filepath:
	certdir = os.path.dirname(filepath)
	os.chdir(certdir)

# Parse command line arguments
parser = argparse.ArgumentParser(
	description='Select which security category to configure',
	formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('-p', '--pwrules', action='store_true', help='configure password rules')
parser.add_argument('-s', '--services', action='store_true', help='configure services')
args = parser.parse_args()

dbfile = 'certify.db'

def initializeDB():
	print "initializing sqlite database"
	try:
		conn = sqlite3.connect(dbfile)
	except:
		print "Could not create sqlite database"
	
	

	exit()

if not os.path.isfile(dbfile):
	initializeDB()

try:
	conn = sqlite3.connect(dbfile)
except:
	print "Could not create sqlite database"

if args.pwrules:
	print "password rules"

elif args.services:
	print "services"
	c = conn.cursor()
else:
	print "You must select a security category"
	exit()
	
