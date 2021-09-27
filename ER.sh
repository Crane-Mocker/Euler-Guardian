##########################################################################
# File Name: ER.sh
# Author: Anaïs Huang
# mail: anaishuangc0conut@gmail.com
# Created Time: Sat 07 Aug 2021 06:31:58 PM CST
# emergency response, automatic analysis
#########################################################################
#!/bin/bash

#PROGRAM_NAME="ER"
#PROGRAM_AUTHOR="c0conut"

# results of scan
scanRes=()
# risk level of each scan
riskLevel=()

#####################################################################
# basic check
# 1. ip_tables
# 2. open ports
# 3. init.d
# 4. $PATH
#####################################################################
function BasicCheck() {

	echo -e "\n\e[1;34miptables (Firewall):\033[0m"
	fwRules=`iptables -L 2>/dev/null`
	fwRulesOnly=`iptables -L 2>/dev/null | egrep -v "Chain|target"`
	if [[ "$fwRulesOnly" == "" ]]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
	else
		scanRes[${#scanRes[*]}]="Found"
		riskLevel[${#riskLevel[*]}]="normal"
	fi
	echo "$fwRules"

	echo -e "\n\e[1;34mOpen ports (TCP and UDP):\033[0m"
	openPorts=`netstat -tulpe | awk '{print $1,$4,$7}' | grep -v "dist" | grep "^[a-z]"`
	if [[ "$openPorts" == "" ]]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. No open TCP and UDP port\033[0m"
	else
		scanRes[${#scanRes[*]}]=`netstat -tulpe | awk '{print $1,$4,$7}' | grep -v "dist" | grep "^[a-z]" | wc -l`
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;34mprotocol addr:port user\033[0m"
		echo -e "$openPorts"
	fi

	echo -e "\n\e[1;34mServices can be started and stopped manually:\033[0m"
	ls -alt /etc/init.d 2>/dev/null
	tmpCnt=`ls -alt /etc/init.d 2>/dev/null | wc -l`
	let tmpCnt-=2
	scanRes[${#scanRes[*]}]=$tmpCnt
	riskLevel[${#riskLevel[*]}]="normal"

	echo -e "\n\e[1;34mPATH:\033[0m"
	echo $PATH
	pathTimes=`echo $PATH | grep -o : | wc -l`
	let pathTimes++
	scanRes[${#scanRes[*]}]=$pathTimes
	riskLevel[${#riskLevel[*]}]="normal"
}

#####################################################################
# sensitive files check
# 1. unusual module that are loaded in kernel
#
#####################################################################
function SensitiveFileCheck() {
	echo -e "\n\e[1;34mChecking unusual modules loaded in kernel.\033[0m"
	unusualMod=`lsmod | egrep -v "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6ta ble_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4|sb_edac|acpi_cpufreq|ixgbe|pf_ring|tcp_htcp|cfg80211|x86_pkg_temp_thermal|mei_me|mei|processor|thermal_sys|lp|enclosure|ses|ehci_pci|igb|i2c_i801|pps_core|isofs|nls_utf8|xt_REDIRECT|xt_multiport|iosf_mbi|qxl|cdc_ether|usbnet|bluetooth" 2>/dev/null`
	if [[ "$unusualMod" == "" ]]; then
		echo -e "\e[1;32mNormal. No unusual module found\033[0m"
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
	else
		scanRes[${#scanRes[*]}]=`echo "$unusualMod" | wc -l`
		riskLevel[${#riskLevel[*]}]="high"
		while read line; do
			IFS=" "
			tmpArr=($line)
			echo -e "\e[1;31mHigh risk. Module: ${tmpArr[0]}\033[0m"
		done <<< "$unusualMod"
	fi
}

#####################################################################
# changed files check
# 1. the opened file which has been deleted
# 2. the file whose ctime changed in the past 7 days
#####################################################################
function FilesChanged() {
	echo -e "\n\e[1;34mChecking files that are opened but have been deleted.\033[0m"
	# drop the first line
	delFileOpened=`lsof -nP +L1 2>/dev/null| grep '(deleted)' | grep -v 'chrome'`
	if [[ "$delFileOpened" == "" ]]; then
		echo -e "\e[1;32mNormal. No deleted but opened files\033[0m"
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
	else
		scanRes[${#scanRes[*]}]=`echo "$delFileOpened" | wc -l`
		riskLevel[${#riskLevel[*]}]="low"
		while read line; do
			IFS=" "
			tmpArr=($line)
			echo -e "\e[1;33mLow risk. Command: ${tmpArr[0]} PID: ${tmpArr[1]} User: ${tmpArr[2]} File path: ${tmpArr[9]}\033[0m"
		done <<< "$delFileOpened"
	fi

	echo -e "\n\e[1;34mChecking files that are changed in 7 days.\033[0m"
	FilesCtime=`find /etc /bin /lib /sbin /dev /root/ /home /tmp /opt /var ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -ctime -7 -type f 2>/dev/null| egrep -v "\.log|cache|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n" | xargs -i{} ls -alh {} 2>/dev/null`
	if [[ "$FilesCtime" == "" ]]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="low"
		echo -e "\e[1;32mNormal. No files changed in 7 days\033[0m"
	else
		scanRes[${#scanRes[*]}]=`echo "$FilesCtime" | wc -l`
		riskLevel[${#riskLevel[*]}]="low"
		while read line; do
			IFS=" "
			tmpArr=($line)
			echo -e "\e[1;33mLow risk. Changed time: ${tmpArr[5]} ${tmpArr[6]} File path: ${tmpArr[8]}\033[0m"
		done <<< "$FilesCtime"
	fi
}

#####################################################################
# process analysis
# 1. process that uses CPU too much
#
#####################################################################
function ProcAnalyse() {
	echo -e "\n\e[1;34mChecking proc that uses CPU a lot.\033[0m"
	procCPU=`ps -aux 2>/dev/null | grep -v PID | sort -rn -k3 | head | awk '{print $1,$2,$3,$4,$11}'`
	# USER PID percent
	#echo "$procCPU"
	tmpCnt=0
	while read line; do
		IFS=" "
		tmpArr=($line)
		#echo "${tmpArr[2]}"
		# use more than 30% CPU
		if [ `echo "${tmpArr[2]}>30.0" | bc` -eq 1 ]; then
			echo -e "\e[1;33mLow risk. Proc ${tmpArr[1]} uses ${tmpArr[2]}% CPU \033[0m"
			let tmpCnt++
		fi
	done <<< "$procCPU"
	if [[ $tmpCnt -eq 0 ]]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. No proc that uses CPU a lot found\033[0m"
	else
		scanRes[${#scanRes[*]}]=$tmpCnt
		riskLevel[${#riskLevel[*]}]="low"
	fi
}

#####################################################################
# hidden process check
# 1. find hidden process
#####################################################################
function HiddenProc() {
	echo -e "\n\e[1;34mChecking hidden processes.\033[0m"

	psPIDList=()
	psPID=`ps -ef 2>/dev/null | awk 'NR>1{print $2}'`
	for eachPID in $psPID; do
		psPIDList[${#psPIDList[*]}]=$eachPID
	done
	#echo "psPID num: ${#psPIDList[*]}"

	procPIDList=()
	procPID=`ls /proc/ | grep ^[0-9]`
	for eachPID in $procPID; do
		procPIDList[${#procPIDList[*]}]=$eachPID
	done
	#echo "procPID num: ${#procPIDList[*]}"

	if [[ ${#psPIDList[*]} -eq ${#procPIDList[*]} ]]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. No hidden process found.\033[0m"
	else
		# compare differences of 2 lists and sort
		hiddenPID=`echo ${psPIDList[@]} ${procPIDList[@]} | tr ' ' '\n' | sort -n | uniq -u`
		scanRes[${#scanRes[*]}]=$hiddenPID
		riskLevel[${#riskLevel[*]}]="high"
		for eachPID in $hiddenPID; do
			echo -e "\e[1;31mHigh risk. Found hidden process, PID: $eachPID\033[0m"
		done
	fi
}

#####################################################################
# history check
# 1. wget in history
# 2. ssh in history
# 3. ssh login (as root) brute-force
#####################################################################
function HistoryCheck() {
	echo -e "\n\e[1;34mChecking wget in sh history\033[0m"
	tmpHistoryWget=`history | grep wget 2>/dev/null`
	if [[ "$tmpHistoryWget" == "" ]]; then
		echo -e "\e[1;32mNormal. No wget history found\033[0m"
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
	else
		scanRes[${#scanRes[*]}]=`echo "$tmpHistoryWget" | wc -l`
		riskLevel[${#riskLevel[*]}]="low"
		echo -e "\e[1;34mHere are wget operations in history:\033[0m"
		echo -e "$tmpHistoryWget"
	fi

	echo -e "\n\e[1;34mChecking SSH in sh history\033[0m"
	tmpHistorySSH=`history | grep ssh 2>/dev/null`
	if [[ "$tmpHistorySSH" == "" ]]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. No SSH history found\033[0m"
	else
		scanRes[${#scanRes[*]}]=`echo "$tmpHistorySSH" | wc -l`
		riskLevel[${#riskLevel[*]}]="low"
		echo -e "\e[1;34mHere are ssh operations in history:\033[0m"
		echo -e "$tmpHistorySSH"
	fi

	echo -e "\n\e[1;34mChecking ssh login brute-force:\033[0m"
	loginTimes=`lastb | grep root | wc -l`
	if [ $loginTimes -gt 50 ]; then
		loginIPs=`lastb | grep root | awk '{print $3}' | sort | uniq 2>/dev/null`
		scanRes[${#scanRes[*]}]=`echo "$loginIPs" | wc -l`
		riskLevel[${#riskLevel[*]}]="high"
		echo -e "\e[1;31mHigh risk. These IPs tried to login as root:\n$loginIPs\033[0m"
		echo -e "\e[0;35mSuggestion: Add unauthorized IPs to blacklist\033[0m"
	else
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. No SSH login brute-force found\033[0m"
	fi
}

#####################################################################
# user analysis
# 1. check user whose UID=0 except root
# 2. users without password
# 3. users who can log in
# 4. all users last log in
#####################################################################
function UserAnalyse() {
	echo -e "\n\e[1;34mChecking user UID=0.\033[0m"
	rootUsers=`awk -F: '{if($3==0)print $1}' /etc/passwd`
	tmpCnt=0
	for eachUser in $rootUsers; do
		if [[ "$eachUser" == "root" ]]; then
			echo -e "\e[1;32mNormal. Found root user: $eachUser\033[0m"
		else
			let tmpCnt++
			echo -e "\e[1;31mHigh risk. Found root user: $eachUser\033[0m"
		fi
	done
	if [ $tmpCnt -eq 0 ]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
	else
		scanRes[${#scanRes[*]}]=$tmpCnt
		riskLevel[${#riskLevel[*]}]="high"
	fi

	echo -e "\n\e[1;34mChecking user without password.\033[0m"
	pwUsers=`awk -F: 'length($2)==0 {print $1}' /etc/shadow 2>/dev/null`
	if [[ "$pwUsers" == "" ]]; then
		echo -e "\e[1;32mNormal. Did not find user without password.\033[0m"
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
	else
		for eachUser in $pwUsers; do
			echo -e "\e[1;31mHigh risk. Found user without password: $eachUser\033[0m"
		done
		scanRes[${#scanRes[*]}]=`echo "$pwUsers" | wc -l`
		riskLevel[${#riskLevel[*]}]="high"
		echo -e "\e[0;35mSuggestion: Delete the high risk users\033[0m"
	fi

	echo -e "\n\e[1;34mUsers who can log in:\033[0m"
	cat /etc/passwd | grep -E "/bin/bash$"
	scanRes[${#scanRes[*]}]=`cat /etc/passwd | grep -E "/bin/bash$" | wc -l`
	riskLevel[${#riskLevel[*]}]="normal"

	echo -e "\n\e[1;34mAll users last log in:\033[0m"
	lastlog
	tmpCnt=`lastlog | grep -v "^**" | wc -l`
	if [ $tmpCnt -eq 0 ]; then
		scanRes[${#scanRes[*]}]="Not found"
	else
		scanRes[${#scanRes[*]}]=$tmpCnt
	fi
	riskLevel[${#riskLevel[*]}]="normal"
}

#####################################################################
# cron check
# 1.crontab files for root
# 2.cron backdoors
#####################################################################
function CronCheck() {
	echo -e "\n\e[1;34mCrontab files for root:\033[0m"
	crontab -u root -l | grep -v '#'

	echo -e "\n\e[1;34mChecking cron backdoors\033[0m"
	cronFileList=()
	tmpLs=`ls /etc/cron* /var/spool/cron/* 2>/dev/null`
	path=""
	for line in $tmpLs; do
		if [[ "$line" == /* ]]; then
			#dir
			if [[ "$line" == *: ]]; then
				path=${line//:/}
				#echo "path: $path"
			#file
			else
				cronFileList[${#cronFileList[*]}]="$line"
			fi
		else
			cronFileList[${#cronFileList[*]}]="$path/$line"
		fi
		#echo "$line"
	done

	tmp=""
	for (( i = 0; i < ${#cronFileList[*]}; i++ )); do
		tmp=`cat ${cronFileList[i]} | grep '((?:useradd|groupadd|chattr)|(?:wget\s|curl\s|tftp\s\-i|scp\s|sftp\s)|(?:bash\s\-i|fsockopen|nc\s\-e|sh\s\-i|\"/bin/sh\"|\"/bin/bash\"))' 2>/dev/null`
		if [[ "$tmp" != "" ]]; then
			echo -e "\e[1;31mHigh risk. Found cron backdoor: ${cronFileList[i]}\033[0m"
		fi
	done
	if [[ "$tmp" == "" ]]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. No cron backdoor found.\033[0m"
	else
		scanRes[${#scanRes[*]}]=${#cronFileList[*]}
		riskLevel[${#riskLevel[*]}]="high"
	fi
}

#####################################################################
# webshell check
# check php asp jsp webshell
#####################################################################
function tmpIsEmpty() {
	if [[ "$tmp" == "" ]]; then
		return 1
	fi
	echo -e "\e[1;31mHigh risk. Backdoor found: $tmp\033[0m"
	return 0
}

function WebshellCheck() {
	wwwExist=`ls /var/www/ 2>/dev/null`
	if [[ "$wwwExist" == "" ]]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. Did not find /var/www/.\033[0m"
	else
		echo -e "\e[1;32mphp webshell:\033[0m"
		tmp=`find /var/www/ -name "*.php" |xargs egrep 'assert|phpspy|c99sh|milw0rm|eval|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec|passthru|\(\$\_\POST\[|eval \(str_rot13|\.chr\(|\$\{\"\_P|eval\(\$\_R|file_put_contents\(\.\*\$\_|base64_decode'`
		tmpIsEmpty
		tmp=`find /var/www/ -name "*.php" |xargs egrep '^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php'`
		tmpIsEmpty
		tmp=`find /var/www/ -name "*.php" |xargs egrep '\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))'`
		tmpIsEmpty
		tmp=`find /var/www/ -name "*.php" |xargs egrep '\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))'`
		tmpIsEmpty
		tmp=`find /var/www/ -name "*.php" |xargs egrep "\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?[\'\"]php:\/\/input"`
		tmpIsEmpty

		echo -e "\e[1;32masp webshell:\033[0m"
		tmp=`find /var/www/ -name "*.asp" |xargs egrep '<%@codepage=65000[\s\S]*=936:|<%eval\srequest\(\"|<%@\sPage\sLanguage=\"Jscript\"[\s\S]*eval\(\w+\+|<%@.*eval\(Request\.Item'`
		tmpIsEmpty
		echo -e "\e[1;32mjsp webshell:\033[0m"
		tmp=`find /var/www/ -name "*.jsp" |xargs egrep '<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)'`
		tmpIsEmpty

		if [[ $tmp == "" ]]; then
			echo -e "\e[1;32mNormal. No webshell found.\033[0m"
			scanRes[${#scanRes[*]}]="Not found"
			riskLevel[${#riskLevel[*]}]="normal"
		else
			scanRes[${#scanRes[*]}]="Found"
			riskLevel[${#riskLevel[*]}]="high"
		fi
	fi
}

#####################################################################
#  generate report
#####################################################################
function ReportGen() {
	timeStamp=`date "+%s"`

	echo "
	<!DOCTYPE html>
		<html lang='en' dir='ltr'>
			<head>
				<!--This file should be under res/-->
				<meta charset='utf-8'>
				<meta name='viewport' content='width=device-width,initial-scale=1'>
				<link href='../template/pic/logo.ico' type='image/x-icon'>
				<title>Euler Guardian</title>
				<link rel='stylesheet' href='../template/normalize.css'>
				<link rel='stylesheet' type='text/css' href='../template/report.css'>
			</head>
			<body>

	<div class='each-part'>
			<h2><a href='#'>Scan results</a></h2>
			<table>
				<tbody>
					<tr>
						<td>Firewall rules</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[0]}.png) no-repeat;'>
							${scanRes[0]}
						</span>
						</td>
					</tr>
					<tr>
						<td>Open TCP and UDP ports</td>
						<td>
							${scanRes[1]}
						</td>
					</tr>
					<tr>
						<td>init.d service(s)</td>
						<td>
							${scanRes[2]}
						</td>
					</tr>
					<tr>
						<td>PATH</td>
						<td>
							${scanRes[3]}
						</td>
					</tr>
					<tr>
						<td>Unusual kernel module(s)</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[4]}.png) no-repeat;'>
							${scanRes[4]}
						</span>
						</td>
					</tr>
					<tr>
						<td>File(s) deleted but opened</br>(except browser)</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[5]}.png) no-repeat;'>
							${scanRes[5]}
						</span>
						</td>
					</tr>
					<tr>
						<td>File(s) changed in 7 days</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[6]}.png) no-repeat;'>
							${scanRes[6]}
						</span>
						</td>
					</tr>
					<tr>
						<td>Proc(s) using CPU more than 30%</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[7]}.png) no-repeat;'>
							${scanRes[7]}
						</span>
						</td>
					</tr>
					<tr>
						<td>Hidden proc(s)</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[8]}.png) no-repeat;'>
							${scanRes[8]}
						</span>
						</td>
					</tr>
					<tr>
						<td>wget in sh history</td>
						<td>
							${scanRes[9]}
						</td>
					</tr>
					<tr>
						<td>ssh in sh history</td>
						<td>
							${scanRes[10]}
						</td>
					</tr>
					<tr>
						<td>IP(s) trying SSH brute-force as root</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[11]}.png) no-repeat;'>
							${scanRes[11]}
						</span>
						</td>
					</tr>
					<tr>
						<td>UID=0 user(s)</br>(except root)</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[12]}.png) no-repeat;'>
							${scanRes[12]}
						</span>
						</td>
					</tr>
					<tr>
						<td>User(s) without password</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[13]}.png) no-repeat;'>
							${scanRes[13]}
						</span>
						</td>
					</tr>
					<tr>
						<td>User(s) can login</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[14]}.png) no-repeat;'>
							${scanRes[14]}
						</span>
						</td>
					</tr>
					<tr>
						<td>User(s) last login</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[15]}.png) no-repeat;'>
							${scanRes[15]}
						</span>
						</td>
					</tr>
					<tr>
						<td>Cron backdoor(s)</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[16]}.png) no-repeat;'>
							${scanRes[16]}
						</span>
						</td>
					</tr>
					<tr>
						<td>Webshell(s)</td>
						<td>
						<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[17]}.png) no-repeat;'>
							${scanRes[17]}
						</span>
						</td>
					</tr>
				</tbody>
			</table>
		</div>
	" > ./report/ER_${timeStamp}.html

	echo "</body></html>" >> ./report/ER_${timeStamp}.html
}

#####################################################################
#  程序开始
#####################################################################

#banner
echo -e "\e[1;32m-----------------------------------------------"
echo " ___         __              "
echo "(_    /_ _  / _   _ _ _/'_   "
echo "/__(/((-/  (__)(/(// (//(//) "
echo -e "Welcome to use Euler Guardian!"
echo "This is the emergency response module."
echo -e "-----------------------------------------------\033[0m"

# parameter process
# -h
if [[ $1 == "--help" ]]||[[ $1 == "-h" ]]; then
	echo -e "This is the emergency response module of Euler Guardian.\nRoot is needed to run the scan.\nUsage:\n\t-h, --help\t help\n\t-r, --report\t An HTML report will be generated"
	exit
# -r
elif [[ $1 == "--report" ]]||[[ $1 == "-r" ]]; then
	genReport=1
	echo -e "\e[1;34mA scan report will be generated.\033[0m"
# no param or wrong param
else
	genReport=0
	echo -e "\e[1;34mWon't generate a scan report.\033[0m"
fi

echo -e "\n\e[1;34m-----------------------------------------------"
echo "Basic check start"
echo -e "-----------------------------------------------\033[0m"
BasicCheck

echo -e "\n\e[1;34m-----------------------------------------------"
echo "Files check start"
echo -e "-----------------------------------------------\033[0m"
SensitiveFileCheck
FilesChanged

echo -e "\n\e[1;34m-----------------------------------------------"
echo "Process check start"
echo -e "-----------------------------------------------\033[0m"
ProcAnalyse
HiddenProc

echo -e "\n\e[1;34m-----------------------------------------------"
echo "User and log check start"
echo -e "-----------------------------------------------\033[0m"
HistoryCheck
UserAnalyse
CronCheck

echo -e "\n\e[1;34m-----------------------------------------------"
echo "Webshell check start"
echo -e "-----------------------------------------------\033[0m"
WebshellCheck

# generate HTML report
if [ $genReport -eq 1 ]; then
	echo "Generating the report..."
	ReportGen
fi
