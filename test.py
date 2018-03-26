#!/usr/bin/python

file = "/etc/cron.daily/clamav"
f = open(file, 'w')

s = "#!/bin/bash\n"
f.write(s)

s = "# clamav\n\n"
f.write(s)

s = 'wget -r -l1 -np -nH --cut-dirs=3 --no-check-certificate "https://zdiv-yum/software/VendorSoftware/clam" -P "/var/lib/clamav" -A "*.cvd"'
s = s + "\n\n"
f.write(s)

s = "cp /var/lib/clamav/*.cvd /var/www/html/software/VendorSoftware/clam/\n\n"
f.write(s)

s = "/usr/local/sbin/clamscan.sh &\n"
f.write(s)

f.close()
