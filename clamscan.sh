#!/bin/bash
# clamscan.sh
# By: Rich O'Hare

# Directories to check
dirs="/bin /boot /etc /home /lib /lib64 /opt /root /sbin /usr /var"

dscan() {
	dir=$1
	if [ -d ${dir} ]; then
		logger -t clamav "${dir}"
		ret=`/bin/find ${dir} -type f ! -fstype nfs -mtime -2 -print0 | xargs -0 -r clamscan -i | grep '^Infected' 2>&1`
		logger -t clamav "${ret}"
	fi
}

for LINE in ${dirs}
do
	dscan ${LINE}
done

