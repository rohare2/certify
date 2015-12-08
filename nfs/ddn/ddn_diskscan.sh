#!/bin/sh
# $Id$
# $Date$
# ddn_diskscan.sh

# set debug mode
debug=0

ddnCmd="/usr/local/sbin/ddndsh"
ddnConf="/usr/local/etc/ddnapi.conf"
arrays='ddn-1a,ddn-2a'
dbhost="corbin"
pw='y0wm0ma!'

if [ -z $ddnCmd ]; then
	echo "Error, no ddn command identified"
	exit
fi

if [ -z $arrays ]; then
	echo "Error, no ddn devices identified"
	exit
else
	arrays=${arrays/,/ }
fi

if [ -z $dbhost ]; then
	echo "Error, no database server identified"
	exit
fi

dbupdate() {
	if [[ $debug -eq 1 ]]; then echo "dbupdate()"; fi
	vendor=''
	product=''
	model=''
	serialNo=''

	ret=`mysql -h$dbhost -udiskscan -p$pw -Ddisks -Nse " \
		select count(*) \
		from inventory" 2>&1`
	if [[ $? -eq 0 ]]; then
		continue
	else
		echo "$ret"
		return 1
	fi

	for arg in "$@"; do
		case "$arg" in
			vendor=* )
				vendor="${arg#vendor=}"
				;;

			product=* )
				product="${arg#product=}"
				;;

			model=* )
				model="${arg#model=}"
				;;
			serialNo=* )
				serialNo="${arg#serialNo=}"
				;;
		esac
	done
	cnt=$(mysql -h$dbhost -udiskscan -p$pw -Ddisks -Nse " \
		SELECT count(location) \
		FROM inventory \
		WHERE serialNo='$serialNo'")
	if [[ $cnt -eq 0 ]]; then
		# new drive
		mysql -h$dbhost -udiskscan -p$pw -Ddisks -se " \
			INSERT INTO inventory \
			VALUES ('$location','$vendor','$product','$model','$serialNo','new','',NOW())"
	else
		# existing drive
		ret=($(mysql -h$dbhost -udiskscan -p$pw -Ddisks -Nse " \
			SELECT location,state \
			FROM inventory \
			WHERE serialNo='$serialNo'"))
		dbloc=`echo $ret | awk '{print $1}'`
		dbstate=`echo $ret | awk '{print $2}'`
		if [[ $location == $dbloc ]]; then
			# same location, update state
			mysql -h$dbhost -udiskscan -p$pw -Ddisks -se " \
				UPDATE inventory \
				SET state='present' \
				WHERE serialNo='$serialNo'"
		else
			# location change
			mysql -h$dbhost -udiskscan -p$pw -Ddisks -se " \
				UPDATE inventory \
				SET location='$location', state='moved' \
				WHERE serialNo='$serialNo'"
		fi
	fi
}

ret=''
for device in $arrays; do
	echo "ddndsh -w $device disk list"
	ret=`ddndsh -w $device disk list`
done

vendor=''
model=''
serialNo=''
logged=0
ok=0

IFS=''
echo $ret | while read line; do
	if [[ $line =~ 'Disk\s' ]]; then
		if [[ $line =~ 'Model:' ]]; then
			model=`echo $line | sed -e 's/\s*Model:\s*/model=/'`
		fi
		if [[ $line =~ 'Serial Number:' ]]; then
			serialNo=`echo $line | sed -e 's/\s*Serial Number:\s*/serialNo=/'`
		fi
		if [[ $line =~ 'Vendor:' ]]; then
			vendor=`echo $line | sed -e 's/\s*Vendor:\s*/vendor=/'`
		fi
		if [[ $serialNo != '' && $model != '' && $vendor != '' && $logged -eq 0 ]]; then
			logger "$location $vendor $model $serialNo"
			if [[ $ok -eq 1 ]]; then
				dbupdate $vendor $model $serialNo
			fi
			logged=1
		fi
	fi
done

