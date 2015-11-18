
ddnCmd="ddndsh"
arrays='ddn-1a,ddn-2a'
dbhost="corbin"

if [ -z $ddnCmd ]; then
	echo "Error, no ddn command identified"
	exit
fi

if [ -z $arrays ]; then
	echo "Error, no ddn devices identified"
	exit
else
	arrays=${arrays/,/ }
fi

if [ -z $dbhost ]; then
	echo "Error, no database server identified"
	exit
fi

for device in $arrays; do
	if [ $ddnCmd = "ddndsh" ]; then
		echo "/admin/scripts/ddndsh -w $device disk list"
	else
		echo "$Unknown command: $ddnCmd"
		exit
	fi
done

