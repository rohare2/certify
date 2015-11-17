#!/bin/sh
# $Id$
# $Date: Thu Sep 3 08:40:55 2015 -0700$

# Uncomment the following line to set debug mode
debug=0

location=`uname -n`
product=''
vendor=''
bus_list=''
logged=0
LSHW='/usr/sbin/lshw'

lsi() {
	if [[ $debug -eq 1 ]]; then echo "lsi($1)"; fi
	enclosure=''
	vendor=''
	slot=''
	inquiryData=''
	fw=''
	model=''
	serialNo=''
	logged=0
	bus=`echo $1 | sed -e 's/.*bus_info= *//' -e 's/:.*//'`
	if [[ ! $bus_list =~ $bus ]]; then 
		bus_list="$bus_list $bus"
		if [[ $debug -eq 1 ]]; then echo "MegaCli64 -PDList -aALL -NoLog"; fi
		/opt/MegaRAID/MegaCli/MegaCli64 -PDList -aALL -NoLog | while read line; do
			# Get "Inquiry Data:"
			if [[ $line =~ 'Enclosure Device ID:' ]]; then
				enclosureID=`echo $line | sed -e 's/Enclosure Device ID: /enclosureID=/'`
				vendor=''
				slot=''
				inquiryData=''
				model=''
				serialNo=''
				logged=0
			fi
			if [[ $line =~ 'Slot Number:' ]]; then
				slotID=`echo $line | sed -e 's/Slot Number: /slotID=/'`
			fi
			if [[ $line =~ 'Inquiry Data:' ]]; then
				inquiryData=$line
				if [[ $debug -eq 1 ]]; then echo "$inquiryData"; fi
			fi
			if [[ $enclosureID != '' && $slotID != '' && $inquiryData != '' && $logged -eq 0 ]]; then
				inquiryData=`echo $line | awk '{print $3}'`
				model=${inquiryData:8:20}
				if [[ $model == ST* ]]; then
					vendor='SEAGATE'
					serialNo=${inquiryData:0:8}
				else 
					serialNo=`echo $line | awk '{print $3}'`
					vendor=`echo $line | awk '{print $4}'`
					model=`echo $line | awk '{print $5}'`
				fi
				if [[ $debug -eq 1 ]]; then echo "$enclosureID, $slotID, model=${model}, serialNo=${serialNo}"; fi
				logger "$enclosureID $slotID vendor=${vendor} model=${model} serialNo=${serialNo}"
				logged=1
			fi
		done

	fi
}

dell() {
	if [[ $debug -eq 1 ]]; then echo "dell($1)"; fi
	enclosureID=''
	slotID=''
	vendor=''
	serialNo=''
	logged=1
	bus=`echo $1 | sed -e 's/.*bus_info= *//' -e 's/:.*//'`
	if [[ ! $bus_list =~ $bus ]]; then 
		bus_list="$bus_list $bus"
		if [[ $debug -eq 1 ]]; then echo "MegaCli64 -PDList -aALL -NoLog"; fi
		/opt/MegaRAID/MegaCli/MegaCli64 -PDList -aALL -NoLog | while read line; do
			# Get "Inquiry Data:"
			if [[ $line =~ 'Enclosure Device ID:' ]]; then
				enclosureID=`echo $line | sed -e 's/Enclosure Device ID: /enclosureID=/'`
				slotID=''
				vendor=''
				model=''
				serialNo=''
				logged=0
			fi
			if [[ $line =~ 'Slot Number:' ]]; then
				slotID=`echo $line | sed -e 's/Slot Number: /slotID=/'`
			fi
			if [[ $line =~ 'Inquiry Data:' ]]; then
				vendor=`echo $line | awk '{print $3}'`
				model=`echo $line | awk '{print $4}'`
				serialNo=`echo $line | awk '{print $5}'`
			fi
			if [[ $enclosureID != '' && $slotID != '' && $serialNo != '' && $logged -eq 0 ]]; then
				logger "$enclosureID $slotID vendor=${vendor} model=${model} serialNo=${serialNo}"
				logged=1
			fi
		done

	fi
}

hpac() {
	if [[ $debug -eq 1 ]]; then echo "hpac()"; fi
	hpacucli controller all show | while read line; do
		if [[ $line =~ 'Smart Array.*Slot' ]]; then
			slot=`echo $line | sed '^.*Slot/Slot/' | awk '{print $2}'`
			drive=''
			serialNo=''
			model=''
			logged=0
			hpacucli controller slot=${slot} physicaldrive all show detail | while read line; do
				if [[ $line =~ 'physicaldrive' ]]; then
					drive=`echo $line | sed 's/\s*physicaldrive\s*/drive=/'`
					serialNo=''
					model=''
					logged=0
				fi
				if [[ $line =~ 'Serial Number:' ]]; then
					serialNo=`echo $line | sed -e 's/\s*/ /' -e 's/\s*Serial Number:\s*/serialNo='`
				fi
				if [[ $line =~ 'Model:' ]]; then
					model=`echo $line | sed -e 's/\s*/ /' -e 's/\s*Model:\s*/model=/'`
				fi
				if [[ $drive != '' && $serialNo != '' && $model != '' && $logged -eq 0 ]]; then
					logger "$drive vendor=HP $model $serialNo"
					logged=1
				fi
			done
		fi
	done
}

directAccess() {
	if [[ $debug -eq 1 ]]; then echo "directAccess()"; fi
	disk=''
	product=''
	vendor=''
	serialNo=''
	logged=0
	$LSHW -class disk | while read line; do
		if [[ $line =~ '-disk' ]]; then
			product=''
			vendor=''
			serialNo=''
			logged=0
		fi
		if [[ $line =~ 'product:' ]]; then
			product=`echo $line | sed -e 's/\s*product:\s*/product=/'`
		fi
		if [[ $line =~ 'vendor:' ]]; then
			vendor=`echo $line | sed -e 's/\s*vendor:\s*/vendor=/'`
		fi
		if [[ $line =~ 'serial:' ]]; then
			serialNo=`echo $line | sed -e 's/\s*serial:\s*/serialNo=/'`
		fi
		if [[ $product =~ 'VBOX HARDDISK' || $product =~ 'VBOX CD-ROM' ]]; then
			continue
		fi
		if [[ $serialNo != '' && $product != '' && ! $vendor =~ 'LSI' && ! $vendor =~ 'DELL' && $logged -eq 0 ]]; then
			logger "$disk $product $vendor $serialNo"
			logged=1
		fi
	done
}

megaRaid() {
	if [[ $debug -eq 1 ]]; then echo "megaRaid()"; fi
	$LSHW -class disk | while read line; do
		if [[ $line =~ '-disk:' ]]; then
			disk=`echo $line | sed -e 's/.*-disk:/disk=/'`
			product=''
			vendor=''
			bus=''
			serial=''
			logged=0
		fi
		if [[ $line =~ 'product:' ]]; then
			product=`echo $line | sed -e 's/: /=/'`
		fi
		if [[ $line =~ 'vendor:' ]]; then
			vendor=`echo $line | sed -e 's/: /=/'`
		fi
		if [[ $line =~ 'bus info:' ]]; then
			bus=`echo $line | sed -e 's/: /=/' -e 's/bus info/bus_info/' -e 's/ *//'`
		fi
		if [[ $line =~ 'serial:' ]]; then
			serial=`echo $line | sed -e 's/serial: /serialNo=/'`
		fi
		if [[ $product =~ 'VBOX HARDDISK' || $product =~ 'VBOX CD-ROM' ]]; then
			continue
		fi
		if [[ $serial != '' && $bus != '' && $logged -eq 0 ]]; then
			if [[ $vendor =~ '=LSI' ]]; then
				lsi $bus
			elif [[ $vendor =~ '=DELL' ]]; then
				dell $bus
			else
				echo "Oops this shouldn't happen"
			fi
			logged=1
		fi
	done
}

smartArray() {
	if [[ $debug -eq 1 ]]; then echo "smartArray()"; fi
	$LSHW -class storage | while read line; do
		if [[ $line =~ '-disk:' ]]; then
			disk=`echo $line | sed -e 's/.*-disk:/disk=/'`
			product=''
			vendor=''
			bus=''
			serial=''
			logged=0
		fi
		if [[ $line =~ 'product:' ]]; then
			product=`echo $line | sed -e 's/: /=/'`
		fi
		if [[ $line =~ 'vendor:' ]]; then
			vendor=`echo $line | sed -e 's/: /=/'`
		fi
		if [[ $line =~ 'bus info:' ]]; then
			bus=`echo $line | sed -e 's/: /=/' -e 's/bus info/bus_info/'`
		fi
		if [[ $line =~ 'serial:' ]]; then
			serial=`echo $line | sed -e 's/serial: /serialNo=/'`
		fi
		if [[ $product =~ 'VBOX HARDDISK' || $product =~ 'VBOX CD-ROM' ]]; then
			continue
		fi
		if [[ $bus != '' && $logged -eq 0 ]]; then
			if [[ $vendor =~ '=Hewlett-Packard' ]]; then
				hpac
			else
				echo "Oops this shouldn't happen"
			fi
			logged=1
		fi
	done
}

hdparm() {
	if [[ $debug -eq 1 ]]; then echo "hdparm()"; fi
	device=$1
	model=''
	serialNo=''
	/sbin/hdparm -I $device | while read line; do
		if [[ $line =~ 'Model Number:' ]]; then
			model=`echo $line | sed 's/\s*Model Number:\s*/model=/'` 
		fi
		if [[ $line =~ 'Device:' ]]; then
			model=`echo $line | sed 's/\s*Model Number:\s*/model=/'` 
		fi
		if [[ $line =~ 'Serial Number:' ]]; then
			serialNo=`echo $line | sed 's/\s*Serial Number:\s*/serialNo=/'`
		fi
		if [[ $model != '' && $serialNo != '' && $logged -eq 0 ]]; then
			logger "device=$device $model $serialNo"
			logged=1
		fi
	done
}

usbDevice() {
	if [[ $debug -eq 1 ]]; then echo "usbDevice()"; fi
	usb=''
	logicalName=''
	logged=0
	$LSHW -class disk | while read line; do
		if [[ $line =~ '-disk' && ! $line =~ ':' ]]; then
			usb=1
			logicalName=''
			logged=0
		fi
		if [[ $line =~ 'logical name:' && $usb -eq 1 ]]; then
			logicalName=`echo $line | sed -e 's/\s*logical name:\s*//'`
		fi
		if [[ $logicalName != '' && $logged -eq 0 ]]; then
			hdparm $logicalName
			logged=1
			usb=0
		fi
	done
}

direct=0
IFS=
result=`$LSHW -businfo -class storage`
echo $result | while read line; do
	if [[ $debug -eq 1 ]]; then echo "$line"; fi
	if [[ $line =~ 'Bus info' || $line =~ '=====' ]]; then
		continue
	fi
	if [[ $line =~ 'MegaRAID' ]]; then
		megaRaid
	elif [[ $line =~ 'Smart Array' ]]; then
		smartArray
	elif [[ $line =~ ' RAX ' ]]; then
		usbDevice
	elif [[ $line =~ ' SATA ' && $direct -eq 0 ]]; then
		directAccess
		direct=1
	elif [[ $line =~ ' ATA ' && $direct -eq 0 ]]; then
		directAccess
		direct=1
	fi
done

