#!/bin/sh
# $Id$
# $URL: file:///usr/local/svn/certify/trunk/db/dumpwrapper.sh $
mysqldump -B -R --no-data --compact disks | sed 's/\/\*!50017 DEFINER=`.*`@`.*`\*\///' 
