#!/bin/bash
# clamscan.sh
# By: Rich O'Hare

logger -t clamav "Starting clamscan.sh"

# Root search
find / \( -path /dev -o -path /proc -o -path /sys -o -path /tmp -o -path /var -o -path /home \) -prune -o \( ! -fstype nfs -a ! -type p -a ! -type s \)  -mtime -2 -print0 | xargs -0 -r clamscan -i | grep '^Infected' | logger -t clamav:main  &

# /home
find /home \( ! -fstype nfs -a ! -type p -a ! -type s \) -mtime -2 -print0 | xargs -0 -r clamscan -i | grep '^Infected' | logger -t clamav:home &

# /var
find /var \( ! -fstype nfs -a ! -type p -a ! -type s \) -mtime -2 -print0 | xargs -0 -r clamscan -i | grep '^Infected' | logger -t clamav:var &

