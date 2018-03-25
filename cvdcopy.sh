#!/bin/sh
# cvdcopy.sh
## Copy the clam .cvd files to the web server

# This script is only applicable for providing a custom source.
# It copies the virus definition files from the standard ClamAV
# location to a local web server. ClamAV clients than use wget
# aquire the files.
#
enableClamav=0
clamavServer=0

if [ $enabled == "1" ]; then
	if [ $clamavServer == "1" ]; then
		cp /var/lib/clamav/*.cvd /var/www/html/software/VendorSoftware/clam/
	fi
fi
