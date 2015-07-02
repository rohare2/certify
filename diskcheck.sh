#!/bin/sh
# diskcheck.sh
# $Id$
# $Date: $
interval='1010000' # '0000-00-00 00:00:00'
quiet=0
report=''
mysql_options='--defaults-file=/root/.my.cnf.certify'

# Process command line arguments
if [[ $1 == -q ]]; then
	# print no results
	quiet=1
fi

ret=`mysql $mysql_options -Nse " \
	select count(*) \
	from inventory" 2>&1`
if [[ $? -ne 0 ]]; then
	echo "error: $ret"
	logger "error: $ret"
	exit
fi

# Disks not updated today
cnt=$(mysql $mysql_options -Nse " \
	SELECT count(location) \
	FROM inventory \
	WHERE NOW() - chg_date > '$interval'");

if [[ $cnt -gt 0 ]]; then
	IFS=$'\n'
	arr=($(mysql $mysql_options -se " \
		SELECT serialNo \
		FROM inventory \
		WHERE NOW() - chg_date > '$interval'"));
	unset IFS
	echo ""
	echo "The following disk drives were not updated today:"
	x=0
	while [ $x -lt $cnt ]; do 
		if [[ $quiet -eq 0 ]]; then
			echo "Disk serialNo ${arr[$x]}"
		fi
		report="$report"$'\n'"Disk serialNo ${arr[$x]} not updated"
		x=`expr $x + 1`
	done
else
	if [[ $quiet -eq 0 ]]; then
		echo ""
		echo "All drives accounted for"
	fi
fi

# new today
cnt=$(mysql $mysql_options -Nse "SELECT count(location) FROM inventory WHERE state='new' AND NOW() - chg_date <= '$interval'");

if [[ $cnt -gt 0 ]]; then
	IFS=$'\n'
	arr=($(mysql $mysql_options -se "SELECT serialNo FROM inventory WHERE state='new' AND NOW() - chg_date <= '$interval'"));
	unset IFS
	echo ""
	echo "The following disk drives are new today:"
	x=0
	while [ $x -lt $cnt ]; do 
		if [[ $quiet -eq 0 ]]; then
			echo "Disk serialNo ${arr[$x]}"
		fi
		report="$report"$'\n'"Disk serialNo ${arr[$x]} new"
		x=`expr $x + 1`
	done
else
	if [[ $quiet -eq 0 ]]; then
		echo ""
		echo "No new drives today"
	fi
fi

# moved today
cnt=$(mysql $mysql_options -Nse "SELECT count(location) FROM inventory WHERE state='moved' AND NOW() - chg_date <= '$interval'");

if [[ $cnt -gt 0 ]]; then
	IFS=$'\n'
	arr=($(mysql $mysql_options -se "SELECT serialNo FROM inventory WHERE state='moved' AND NOW() - chg_date <= '$interval'"));
	unset IFS
	echo ""
	echo "The following disk drives moved today:"
	x=0
	while [ $x -lt $cnt ]; do 
		if [[ $quiet -eq 0 ]]; then
			echo "Disk serialNo ${arr[$x]}"
		fi
		report="$report"$'\n'"Disk serialNo ${arr[$x]} moved"
		x=`expr $x + 1`
	done
else
	if [[ $quiet -eq 0 ]]; then
		echo ""
		echo "No drives moved today"
	fi
fi

if [[ $report != '' ]]; then
cat <<EOF | sendmail -t
To: root
From: root
Subject: Daily disk report
`echo "$report"`
EOF

fi
