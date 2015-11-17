#!/bin/sh
# $Id$
# $URL: file:///usr/local/svn/certify/trunk/nfs/sun/sscs_report.sh $

PATH=$PATH:/opt/SUNWsesscs/cli/bin
sscs login -h localhost -u storage
echo "Using CAM version: "
sscs --version

echo "Collecting disk information fro the following JBOD shelves"
sscs list storage-system

for i in `sscs list storage-system | cut -c8-17`; do
	echo "========================================================="
	echo $i;
	echo "========================================================="
	sscs list -a $i disk; 
	echo " "
	echo " "
done
