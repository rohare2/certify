#!/bin/sh
# $Id$
# $URL: $
# netapp_diskscan.sh

# set debug mode
debug=0

if [[ $1 != '' ]]; then
	host=$1
else
	echo "usage: netapp_diskscan.sh {nfs_server_name}"
	exit
fi

vendor=''
model=''
serialNo=''
logged=0
dbhost=''
pw='y0wm0ma!'
ok=0

source /etc/profile.d/yum.sh
ret=`echo $YUM0`
if [[ $? -eq 0 && $YUM0 != '' ]]; then
	dbhost=$YUM0
	ret=`mysql -h$dbhost -udiskscan -Ddisks -p$pw -Nse " \
		select count(*) \
		from inventory" 2>&1`
	if [[ $? -eq 0 ]]; then
		ok=1
	else
		echo "error: $ret"
		logger "error: $ret"
		ok=0
	fi
else
	echo "YUM0 undefined"
	logger "YUM0 undefined"
	ok=0
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

ret=`ssh $location /usr/local/sbin/list_netapp_disks.sh`
IFS=''
echo $ret | while read line; do
	if [[ $line =~ 'Availability:' ]]; then
		vendor=''
		model=''
		serialNo=''
		logged=0
	fi
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
done

