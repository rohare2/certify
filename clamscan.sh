#!/bin/bash
# slamscan.sh
# By: Rich O'Hare

# Directories to check
dirs="/bin /boot /etc /home /lib /lib64 /opt /root /sbin /usr /var"

#how many jobs to run at one time
jobsAtOnce=2

bgxupdate() {
    bgxoldgrp=${bgxgrp}
    bgxgrp=""
    ((bgxcount = 0))
    bgxjobs=" $(jobs -pr | tr '\n' ' ')"
    for bgxpid in ${bgxoldgrp} ; do
        echo "${bgxjobs}" | grep " ${bgxpid} " >/dev/null 2>&1
        if [[ $? -eq 0 ]] ; then
            bgxgrp="${bgxgrp} ${bgxpid}"
            ((bgxcount = bgxcount + 1))
        fi
    done
}


bgxlimit() {
    bgxmax=$1 ; shift
    bgxupdate
    while [[ ${bgxcount} -ge ${bgxmax} ]] ; do
        sleep 1
        bgxupdate
    done
    if [[ "$1" != "-" ]] ; then
        $* &
        bgxgrp="${bgxgrp} $!"
    fi
}

dscan() {
	dir=$1
	if [ -d $dir ]; then
		ret=`/bin/find $dir -type f ! -fstype nfs -mtime -2 -print0 | xargs -0 -r clamscan -i | grep '^Infected' 2>&1 &`
		logger -t clamav "${dir} - $ret"
	fi
}

bgxgrp="process_group_1"
for LINE in $dirs
do
    CMD='uptime'
    bgxlimit $JOBS_AT_ONCE dscan ${LINE}
done

# Wait until all queued processes are done.
bgxupdate
while [[ ${bgxcount} -ne 0 ]] ; do
    oldcount=${bgxcount}
    while [[ ${oldcount} -eq ${bgxcount} ]] ; do
        sleep 1
        bgxupdate
    done
done
