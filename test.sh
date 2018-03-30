# Main search
echo "scanning main"
find / \( -path /dev -o -path /proc -o -path /sys -o -path /tmp -o -path /var -o -path /home \) -prune -o ! -fstype nfs  -mtime -2 -print0 | xargs -0 -r clamscan -i | grep '^Infected' &

# /home
echo "scanning home"
find /home ! -fstype nfs -mtime -2 -print0 | xargs -0 -r clamscan -i | grep '^Infected' &

# /var
echo "scanning var"
find /var ! -fstype nfs -mtime -2 -print0 | xargs -0 -r clamscan -i | grep '^Infected' &
