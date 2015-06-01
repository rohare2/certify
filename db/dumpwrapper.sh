#!/bin/sh
# $Id: dumpwrapper.sh 517 2014-06-07 15:54:18Z rohare $
# $URL: file:///usr/local/svn/certify/trunk/db/dumpwrapper.sh $
mysqldump -B -R --no-data --compact disks | sed 's/\/\*!50017 DEFINER=`.*`@`.*`\*\///' 
