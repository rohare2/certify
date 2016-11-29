#!/bin/bash
# $Id$
# $Date$

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
	inquiryData=''
	vendor=''
	model=''
	serialNo=''
	logged=0
	bus=$1
	if [[ ! $bus_list =~ $bus ]]; then 
		bus_list="$bus_list $bus"
		/opt/MegaRAID/MegaCli/MegaCli64 -PDList -aALL -NoLog | while read line; do
			# Get "Inquiry Data:"
			if [[ $line =~ 'Enclosure Device ID:' ]]; then
				enclosureID=`echo $line | sed -e 's/Enclosure Device ID: /enclosureID=/'`
				inquiryData=''
				vendor=''
				model=''
				serialNo=''
				logged=0
			fi
			if [[ $line =~ 'Inquiry Data:' ]]; then
				inquiryData=$line
			fi
			if [[ $inquiryData =~ 'SEAGATE' ]]; then
				vendor='SEAGATE'
				model=`echo $inquiryData | awk '{print $4}'`
				serialNo=`echo $inquiryData | awk '{print $5}'`
			elif [[ $inquiryData =~ 'SAMSUNG' ]]; then
				vendor=`echo $inquiryData | awk '{print $4}'`
				model=`echo $inquiryData | awk '{print $5}'`
				serialNo=`echo $inquiryData | awk '{print $3}'`
			elif [[ $inquiryData != '' ]]; then
				inquiryData=`echo $inquiryData | awk '{print $3}'`
				vendor='SEAGATE'
				model=${inquiryData:8:20}
				serialNo=${inquiryData:0:8}
			fi

			if [[ $inquiryData != '' && $logged -eq 0 ]]; then
				inquiryData=`echo $inquiryData | awk '{print $3}'`
				if [[ $debug -eq 1 ]]; then
					echo "diskscan: vendor=${vendor} model=${model} serialNo=${serialNo}"
				else
					logger "diskscan: vendor=${vendor} model=${model} serialNo=${serialNo}"
				fi
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
					serialNo=`echo $line | sed -e 's/\s*/ /' -e 's/\s*Serial Number:\s*//'`
				fi
				if [[ $line =~ 'Model:' ]]; then
					model=`echo $line | sed -e 's/\s*/ /' -e 's/\s*Model:\s*/model=/'`
				fi
				if [[ $drive != '' && $serialNo != '' && $model != '' && $logged -eq 0 ]]; then
					if [[ $debug -eq 1 ]]; then
						echo "diskscan: $drive vendor=HP model=$model serialNo=$serialNo"
					fi
					logger "diskscan: $drive vendor=HP model=$model serialNo=$serialNo"
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
		if [[ $line =~ '-disk' || $line =~ '-cdrom' ]]; then
			product=''
			vendor=''
			serialNo=''
			logged=0
		fi
		if [[ $line =~ 'product:' ]]; then
			product=`echo $line | sed -e 's/\s*product:\s*//'`
		fi
		if [[ $line =~ 'vendor:' ]]; then
			vendor=`echo $line | sed -e 's/\s*vendor:\s*//'`
		fi
		if [[ $line =~ 'serial:' ]]; then
			serialNo=`echo $line | sed -e 's/\s*serial:\s*//'`
		fi
		if [[ $product =~ 'VBOX HARDDISK' || $product =~ 'VBOX CD-ROM' ]]; then
			continue
		fi
		if [[ $serialNo != '' && $product != '' && ! $vendor =~ 'LSI' && ! $vendor =~ 'DELL' && $logged -eq 0 ]]; then
			if [[ $debug -eq 1 ]]; then
				echo "diskscan: $disk vendor=${vendor} model=${product} serialNo=${serialNo}"
			fi
			logger "diskscan: $disk vendor=${vendor} model=${product} serialNo=${serialNo}"
			logged=1
		fi
	done
}

megaRaid() {
	if [[ $debug -eq 1 ]]; then echo "megaRaid()"; fi
	# Determine controller version
	controller=`/opt/MegaRAID/MegaCli/MegaCli64 -AdpAllInfo -a0 -NoLog | grep 'Product Name'`
	if [[ $debug -eq 1 ]]; then echo "controller: $controller"; fi
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
			product=`echo $line | sed -e 's/^\s*product: //'`
		fi
		if [[ $line =~ 'vendor:' ]]; then
			vendor=`echo $line | sed -e 's/^\s*vendor: //'`
		fi
		if [[ $line =~ 'bus info:' ]]; then
			bus=`echo $line | sed -e 's/^\s*bus info: //' -e 's/:.*$//'`
		fi
		if [[ $line =~ 'serial:' ]]; then
			serial=`echo $line | sed -e 's/serial: //'`
		fi
		if [[ $product =~ 'VBOX HARDDISK' || $product =~ 'VBOX CD-ROM' ]]; then
			continue
		fi
		if [[ $serial != '' && $bus != '' && $logged -eq 0 ]]; then
			if [[ $controller =~ 'LSI MegaRAID SAS 9260' ||
				$controller =~ 'MegaRAID SAS 8888ELP' ||
				$controller =~ 'PERC' ]]; then
				lsi $bus
			else
				echo "Unknown MegaRAID controller, notify Certify developer"
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
			serial=`echo $line | sed -e 's/serial: //'`
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
			serialNo=`echo $line | sed 's/\s*Serial Number:\s*//'`
		fi
		if [[ $model != '' && $serialNo != '' && $logged -eq 0 ]]; then
			if [[ $debug -eq 1 ]]; then
				echo "diskscan: device=${device} model=${model} serialNo=${serialNo}"
			fi
			logger "diskscan: device=${device} model=${model} serialNo=${serialNo}"
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

