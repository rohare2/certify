#!/bin/bash
dir=$1
if [ -d $dir ]; then
	ret=`/bin/find $dir -type f -mtime -2 -print0 | xargs -0 -r clamscan -i | grep '^Infected' 2>&1 &`
	logger -t clamav "${dir} - $ret"
fi
