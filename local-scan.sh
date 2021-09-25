##########################################################################
# File Name: local-scan.sh
# Author: Anaïs Huang
# mail: anaishuangc0conut@gmail.com
# Created Time: Mon 28 Jun 2021 09:16:21 AM CST
#########################################################################
#!/bin/sh

#PROGRAM_NAME="local_scan"
#PROGRAM_AUTHOR="c0conut"

#######################################################################
# pre operations
# 1. generate timeStamp
# 2. current id check，if UID=0. Can only run as root.
# 3. check SetUID
# 4. delete files left from previous scan
#######################################################################
function PreOp() {

	timeStamp=`date "+%s"`

	local CurrentId=""
	#Solaris
	if [ -x /usr/xpg4/bin/id ]; then
		CurrentId=$(/usr/xpg4/bin/id -u 2>/dev/null)
	elif [ "$(uname)" = "SunOS" ]; then
		CurrentId=$(id | tr '=' ' ' | tr '(' ' ' | awk '{ print $2 }' 2>/dev/null)
	#"$(uname)" = "Linux", for Euler, ubuntu, etc
	else
		CurrentId=$(id -u 2>/dev/null)
		#echo "current id $CurrentId"
	fi

	#check if UID = 0(root)
	if [ ${CurrentId} -ne 0 ]; then
		echo -e "Should run as root!\nExit."
		exit
	fi

	#check SetUID ("s")
	if [ -u "$0" ]; then
		echo -e "\e[0;31mStopped because of unusual SetUID. Exit.\n\033[0m"
		exit
	fi

	rm oscap* res/s.txt 2>/dev/null
}

########################################################################
# system info check
# 1. basic info: OS and its version, kernel and its version,
# platform
########################################################################
function SysInfoChk() {
	tmpStr=`cat /etc/*-release | grep ^NAME=`
	IFS='"'
	read -ra tmpArr <<<"$tmpStr"
	tmpStr1=${tmpArr[1]}
	releaseNameStr=${tmpStr1,,}
	#echo "$releaseNameStr"

	# release version id
	tmpStr=`cat /etc/*-release | grep VERSION_ID 2>/dev/null`
	IFS='"'
	read -ra tmpArr <<<"$tmpStr"
	releaseVersionID=${tmpArr[1]}
	releaseVersionIDStr=`echo ${releaseVersionID//./}`
	echo -e "\e[1;34mOS:\033[0m $releaseNameStr $releaseVersionID"

	local kernelName=`uname -s 2>/dev/null`
	local kernelRelease=`uname -r 2>/dev/null`
	echo -e "\e[1;34mKernel:\033[0m $kernelName $kernelRelease"
	local hardwareP=`uname -i`
	echo -e "\e[1;34mPlatform:\033[0m $hardwareP"

}

####################################################################
# security policy check
# selinux, limitations of resources
####################################################################
function SecCheck() {
	# SElinux
	local SEstatus=`sestatus 2>/dev/null`
	if [ "$SEstatus" ]; then
		echo -e "\e[1;34mSElinux status:\n\033[0m"
		cat /etc/selinux/config | grep SELINUX=
	else
		echo -e "\e[1;33mLow risk. SELinux not found\033[0m"
	fi

	# limitations of resources
	echo -e "\n\e[1;34mLimitations for various resources:\033[0m"
	ulimit -a
}

########################################################################
# user info
# hostname, id, user accounts info, if passwords are stored as hash,
# last login
########################################################################
function UserInfoChk() {
	# hostname
	local Hostname=`hostname 2>/dev/null`
	if [ "$Hostname" ]; then
		echo -e "\e[1;34mHostname: \e[00m$Hostname\n\033[0m" 2>/dev/null
	else
		echo -e "\e[0;36mhostname failed.\n\033[0m" 2>/dev/null
	fi

	#id
	local Id=`id 2>/dev/null`
	if [ "$Id" ]; then
		echo -e "\e[1;34mCurrent user and group IDs:\e[00m\n$Id\n\033[0m" 2>/dev/null
	else
		echo -e "\e[0;36mid failed.\n\033[0m" 2>/dev/null
	fi

	#user accounts info
	local Passwd=`cat /etc/passwd 2>/dev/null | cut -d ":" -f 1,2,3,4 2>/dev/null`
	if [ "$Passwd" ]; then
		echo -e "\e[1;34mUsers and permissions:\033[0m"
		echo -e "\e[0;34mUsername:Password:UID:GID\033[0m"
		echo -e "\e[00m$Passwd\n\033[0m" 2>/dev/null
		#group memebership
		local GroupIdInfo=`for i in $(cat /etc/passwd 2>/dev/null| cut -d":" -f1 2>/dev/null);do id $i;done 2>/dev/null`
		if [ "$GroupIdInfo" ]; then
			echo -e "\e[1;34mGroup memberships:\e[00m\n$GroupIdInfo\n\033[0m" 2>/dev/null
		else
			:
		fi
		#if password stored in /etc/passwd as hash
		local HashPw=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
		if [ "$HashPw" ]; then
			echo -e "\e[1;34mFound password stored in /etc/passwd as hash:\n\033[0m$HashPw\n" 2>/dev/null
		else
			echo -e "\e[0;34mNo password is stored in /etc/passwd as hash.\n\033[0m" 2>/dev/null
		fi
	else
		echo -e "\e[0;36m cat /etc/passwd failed.\n\033[0m" 2>/dev/null
	fi

	#last log for each user
	local LastLogUser=`lastlog 2>/dev/null | grep -v "Never"`
	if [ "$LastLogUser" ]; then
		echo -e "\e[1;34mUsers previously logged onto system:\e[0m\n$LastLogUser\n\033[0m" 2>/dev/null
	else
		echo -e "\e[0;36mCan't find /var/log/lastlog.\n\033[0m" 2>/dev/null
	fi
}

########################################################################
# user identity
# hostname, id, user accounts info, if passwords are stored as hash,
# last login
########################################################################
function UserIdenChk() {
	# basic password configuration
	local pwMaxDay=`cat /etc/login.defs | grep ^PASS 2>/dev/null | grep PASS_MAX_DAYS 2>/dev/null| egrep ^[0-9]`
	local pwMinDay=`cat /etc/login.defs | grep ^PASS 2>/dev/null | grep PASS_MIN_DAYS 2>/dev/null| egrep ^[0-9]`
	local pwMinLen=`cat /etc/login.defs | grep ^PASS 2>/dev/null | grep PASS_MIN_LEN 2>/dev/null| egrep ^[0-9]`
	local pwWarnAge=`cat /etc/login.defs | grep ^PASS 2>/dev/null | grep PASS_WARN_AGE 2>/dev/null| egrep ^[0-9]`

	if [[ "$pwMaxDay" == "" ]] || [[ $pwMaxDay -eq 99999 ]]; then
		echo -e "\e[1;33mLow risk. No limitation of password expired days\033[0m"
	else
		echo -e "\e[1;32mNormal.\e[1;34mDays for a password to expire:\033[0m $pwMaxDay"
	fi

	if [[ "$pwMinDay" == "" ]]; then
		echo -e "\e[1;33mLow risk. No limitation of days to wait after last change of password\033[0m"
	else
		echo -e "\e[1;32mNormal.\e[1;34mMin days to wait after last change of password:\033[0m $pwMinDay"
	fi

	if [[ "$pwMinLen" == "" ]]; then
		echo -e "\e[1;33mLow risk. No limitation of password min length\033[0m"
	else
		echo -e "\e[1;32mNormal.\e[1;34mMin length of password:\033[0m $pwMinLen"
	fi

	if [[ "$pwWarnAge" == "" ]]; then
		echo -e "\e[1;33mLow risk. Did not set a date to get warning before password expiration\033[0m"
	else
		echo -e "\e[1;32mNormal.\e[1;34mDays to receive warning before password expiration:\033[0m $pwWarnAge"
	fi

	#pam password config
	local pamCracklib=`cat /etc/pam.d/system-auth 2>/dev/null | grep pam_cracklib.so 2>/dev/null`
	if [[ "$pamCracklib" == "" ]]; then
		echo -e "\e[1;33mLow risk. Cracklib did not find"
	else
		local pamRetry=`echo $pamCracklib | grep -oE 'retry=[1-9]' 2>/dev/null`
		if [[ "$pamRetry" == "" ]]; then
			pamRetry="Not set"
		else
			pamRetry=${pamRetry#*=}
		fi
		#echo "pamRetry $pamRetry"
		local pamDifok=`echo $pamCracklib | grep -oE 'difok=[1-9]' 2>/dev/null`
		if [[ "$pamDifok" == "" ]]; then
			pamDifok="Not set"
		else
			pamDifok=${pamDifok#*=}
		fi
		#echo "pamDifok $pamDifok"
		local pamMinLen=`echo $pamCracklib | grep -oE 'minlen=[1-9]' 2>/dev/null`
		if [[ "$pamMinLen" == "" ]]; then
			pamMinLen="Not set"
		else
			pamMinLen=${pamMinLen#*=}
		fi
		#echo "pamMinLen $pamMinLen"
		local pamUcredit=`echo $pamCracklib | grep -oE 'ucredit=-[1-9]' 2>/dev/null`
		if [[ "pamUcredit" == "" ]]; then
			pamUcredit="Not set"
		else
			pamUcredit=${pamUcredit#*-}
		fi
		#echo "pamUcredit $pamUcredit"
		local pamLcredit=`echo $pamCracklib | grep -oE 'lcredit=-[1-9]' 2>/dev/null`
		if [[ "$pamLcredit" == "" ]]; then
			pamLcredit="Not set"
		else
			pamLcredit=${pamLcredit#*-}
		fi
		#echo "pamLcredit $pamLcredit"
		local pamDcredit=`echo $pamCracklib | grep -oE 'dcredit=-[1-9]' 2>/dev/null`
		if [[ "$pamDcredit" == "" ]]; then
			pamDcredit="Not set"
		else
			pamDcredit=${pamDcredit#*-}
		fi
		#echo "pamDcredit $pamDcredit"
		local pamDictPath=`echo $pamCracklib | grep -oE 'dictpath=*' 2>/dev/null`
		if [[ "$pamDictPath" == "" ]]; then
			pamDictPath="Not set"
		else
			pamDictPath=${pamDictPath#*=}
		fi
		#echo "pamDictPath $pamDictPath"
		echo -e "\e[1;32mNormal. Cracklib found.\033[0m"
		echo -e "\e[0;32mRetry times: $pamRetry\tMin num of different chars: $pamDifok\nMin length of password: $pamMinLen\tMin num of upper case chars: $pamUcredit\nMin num of lower case chars: $pamLcredit\tMin num of numbers: $pamDcredit\nPassword dictionary path: $pamDictPath\033[0m"
	fi

	# user without password
	echo -e "\n\e[1;34mChecking user without password.\033[0m"
	local pwUsers=`awk -F: 'length($2)==0 {print $1}' /etc/shadow 2>/dev/null`
	if [[ "$pwUsers" == "" ]]; then
		echo -e "\e[1;32mNormal. Did not find user without password.\033[0m"
	else
		for eachUser in $pwUsers; do
			echo -e "\e[1;31mHigh risk. Found user without password: $eachUser\033[0m"
		done
		echo -e "\e[0;35mSuggestion: Delete the high risk users\033[0m"
	fi
}

#######################################################################
# file permission/ownership check
#
#######################################################################
function FilePermChk() {
	# all files with "s" perm
	echo -e "\e[1;34mChecking files which have s permission"
	echo -e "\e[0;34mIt may take several minutes.\033[0m"
	find / -type f -perm -4000 -o -perm -2000 -print 2>/dev/null| xargs ls -al > res/s.txt
	# s.txt size != 0
	if [ $(du -b res/s.txt | grep -oE ^[0-9]*) -ne 0 ]; then
		echo -e "\e[1;33mLow risk. Files with s perm found. Please check them in res/s.txt\033[0m"
	# s.txt size == 0
	else
		echo -e "\e[1;32mNormal. No files with s perm found\033[0m"
	fi

	# 777 perm files belonged to nogroup
	echo -e "\n\e[1;34mChecking files have 777 perms without group belonged to\033[0m"
	file777Perm=`find / -perm 777 -nogroup 2>/dev/null`
	if [[ "$file777Perm" == "" ]]; then
		echo -e "\e[1;32mNormal. No files having 777 perm without group belonged to\033[0m"
	else
		echo -e "\e[1;31mHigh risk. Found:\n\033[0m$file777Perm"
	fi

	# orphan files
	echo -e "\n\e[1;34mChecking orphan files\033[0m"
	orphanFile=`find / -nouser -o -nogroup 2>/dev/null`
	if [[ "$orphanFile" == "" ]]; then
		echo -e "\e[1;32mNormal. No orphan file found\033[0m"
	else
		echo -e "\e[1;31mHigh risk. Found:\n\033[0m$orphanFile"
	fi

	echo -e "\n\e[1;34mChecking unusual modules loaded in kernel.\033[0m"
	unusualMod=`lsmod | egrep -v "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6ta ble_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4|sb_edac|acpi_cpufreq|ixgbe|pf_ring|tcp_htcp|cfg80211|x86_pkg_temp_thermal|mei_me|mei|processor|thermal_sys|lp|enclosure|ses|ehci_pci|igb|i2c_i801|pps_core|isofs|nls_utf8|xt_REDIRECT|xt_multiport|iosf_mbi|qxl|cdc_ether|usbnet|bluetooth" 2>/dev/null`
	if [[ "$unusualMod" == "" ]]; then
		echo -e "\e[1;32mNormal. No unusual module found\033[0m"
	else
		while read line; do
			IFS=" "
			tmpArr=($line)
			echo -e "\e[1;33mLow risk. Module: ${tmpArr[0]}\033[0m"
		done <<< "$unusualMod"
	fi
}

#######################################################################
# audit system check
#
#######################################################################
function AuditChk() {
	if [ "$(apt -v 2>/dev/null)" ]; then
		if [ "$(auditd 2>/dev/null)" ]; then
			echo -e "\e[1;32mNormal. Linux Auditing System found.\033[0m"
		else
			echo -e "\e[1;33mLow risk. No Linux Auditing System\033[0m"
		fi
	elif [ "$(yum --version 2>/dev/null)" ]; then
		if [ "$(yum list audit audit-libs 2>/dev/null | grep audit)" ]; then
			echo -e "\e[1;32mNormal. Linux Auditing System found.\033[0m"
		else
			echo -e "\e[1;33mLow risk. No Linux Auditing System\033[0m"
		fi
	fi
}

####################################################################
# vuln check according to OVAL file
####################################################################
function OVALChk() {
	# install oscap
	if [ "$(apt -v 2>/dev/null)" ]; then
		# use apt
		echo -e "\e[1;34mThis device uses apt.\n\033[0m" 2>/dev/null
		# if oscap is installed
		if [ "$(oscap -h 2>/dev/null)" ]; then
			:
		else
			echo -e "\e[1;34mNo oscap. Downloading...\n\033[0m" 2>/dev/null
			sudo apt-get install libopenscap8
		fi
	elif [ "$(yum --version 2>/dev/null)" ]; then
		# use yum
		echo -e "\e[1;34mThis device uses yum.\n\033[0m" 2>/dev/null

		# if oscap is installed
		if [ "$(oscap -h 2>/dev/null)" ]; then
			:
		else
			echo -e "\e[1;34mNo oscap. Downloading...\n\033[0m" 2>/dev/null
			sudo yum install openscap-utils -y
		fi
	fi

	# check OVAL file
	# release id
	tmpStr=`cat /etc/*-release | grep ^NAME=`
	IFS='"'
	read -ra tmpArr <<<"$tmpStr"
	tmpStr1=${tmpArr[1]}
	releaseNameStr=${tmpStr1,,}
	#echo "$releaseNameStr"

	# release version id
	tmpStr=`cat /etc/*-release | grep VERSION_ID 2>/dev/null`
	IFS='"'
	read -ra tmpArr <<<"$tmpStr"
	releaseVersionID=${tmpArr[1]}
	releaseVersionIDStr=`echo ${releaseVersionID//./}`
	#echo "$releaseVersionIDStr"

	#default ssg:centos7 oval:redhat7
	targetSSGFile="ssg-${releaseNameStr}${releaseVersionIDStr}-ds.xml"
	targetOVALFile="${releaseNameStr}${releaseVersionIDStr}.oval.xml"

	hasSSGFile=`ls ssg | grep ${targetSSGFile} 2>/dev/null`
	if [ "$hasSSGFile" ]; then
		# ssg check
		echo -e "\e[1;34mSSG file found:\e[00m\n$targetSSGFile\033[0m"
		oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_standard --results ./report/sec_conf_${timeStamp}.xml --report ./report/sec_conf_${timeStamp}.html ./ssg/${targetSSGFile}
	else
		echo -e "\e[1;34mNo SSG file found. Use centos7.\033[0m"
		oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_standard --results ./report/sec_conf_${timeStamp}.xml --report ./report/sec_conf_${timeStamp}.html ./ssg/ssg-centos7-ds.xml
	fi

	hasOVALFile=`ls ssg | grep ${targetOVALFile} 2>/dev/null`
	if [ "$hasOVALFile" ]; then
		#echo "has oval file"
		echo -e "\e[1;34mOVAL file found:\e[00m\n$targetOVALFile\033[0m"
		oscap oval eval --results ./report/comp_vuln_${timeStamp}.xml --report ./report/comp_vuln_${timeStamp}.html ./ssg/${targetOVALFile}
	else
		targetOVALFile="${releaseNameStr}.oval.xml"
		hasOVALFile=`ls ssg | grep ${targetOVALFile} 2>/dev/null`
		if [ "$hasOVALFile" ]; then
			echo -e "\e[1;34mOVAL file found:\e[00m\n$targetOVALFile\033[0m"
			oscap oval eval --results ./report/comp_vuln_${timeStamp}.xml --report ./report/comp_vuln_${timeStamp}.html ./ssg/${targetOVALFile}
		else
			echo -e "\e[1;34mNo OVAL file found. Use rhel7.\033[0m"
			oscap oval eval --results ./report/comp_vuln_${timeStamp}.xml --report ./report/comp_vuln_${timeStamp}.html ./ssg/rhel7.oval.xml
		fi
	fi

	echo -e "\e[1;34mPlease check for the results in report dir\033[0m" 2>/dev/null

}

#####################################################################
#  create report
#####################################################################
function ReportHead() {

	echo "<!DOCTYPE html>
	<html lang='en' dir='ltr'>
		<head>
			<meta charset='utf-8'>
			<meta name='viewport' content='width=device-width,initial-scale=1'>
			<script src='https://rawgit.com/aFarkas/html5shiv/gh-pages/dist/html5shiv.min.js'></script>
			<link rel='stylesheet' href='normalize.css'>
			<title></title>
		</head>
		<body>" > ./report/EG_report_${timeStamp}.html
}

function ReportFoot() {
	timeStamp2Date=`date -d @${timeStamp}`
	echo "<div>$timeStamp2Date</div>
	</body></html>" >> ./report/EG_report_${timeStamp}.html
}

#####################################################################
#  Program Starts
#####################################################################

#banner
echo -e "\e[1;32m-----------------------------------------------"
echo " ___         __              "
echo "(_    /_ _  / _   _ _ _/'_   "
echo "/__(/((-/  (__)(/(// (//(//) "
echo -e "Welcome to use Euler Guardian!"
echo "This is the local scan module."
echo -e "-----------------------------------------------\033[0m"

# parameter process
# -h
if [[ $1 == "--help" ]]||[[ $1 == "-h" ]]; then
	echo -e "This is the local scan module of Euler Guardian.\nRoot is needed to run the scan.\nAn HTML report will be generated according to the scan results.\nUsage:\n\t-h, --help\t help\n\t-s, --silent\t Do not display details"
# -s
elif [[ $1 == "--silent" ]]||[[ $1 == "-s" ]]; then
	isSilent=1
	echo -e "Silent mode is chosen."
# no param or wrong param
else
	isSilent=0
	echo -e "Silent mode is not chosen."
fi

echo -e "\n\e[1;34m-----------------------------------------------"
echo "System information check"
echo -e "-----------------------------------------------\033[0m"
PreOp
SysInfoChk
SecCheck

echo -e "\n\e[1;34m-----------------------------------------------"
echo "Users information and access control check"
echo -e "-----------------------------------------------\033[0m"
UserInfoChk
UserIdenChk

echo -e "\n\e[1;34m-----------------------------------------------"
echo "Files permissions check"
echo -e "-----------------------------------------------\033[0m"
FilePermChk

echo -e "\n\e[1;34m-----------------------------------------------"
echo "Software vuln check"
echo -e "-----------------------------------------------\033[0m"
OVALChk
