##########################################################################
# File Name: ER.sh
# Author: Anaïs Huang
# mail: anaishuangc0conut@gmail.com
# Created Time: Sat 07 Aug 2021 06:31:58 PM CST
# 应急响应 自动分析
#########################################################################
#!/bin/bash

#PROGRAM_NAME="ER"
#PROGRAM_AUTHOR="c0conut"

#####################################################################
# 基本检查
# /tmp下文件，services, $PATH
#####################################################################
function BasicCheck() {
	echo -e "\e[1;32mFiles under /tmp:\n\033[0m"
	ls -alt /tmp 2>/dev/null

	echo -e "\e[1;32mServices can be started and stopped manually:\n\033[0m"
	ls -alt /etc/init.d 2>/dev/null

	echo -e "\e[1;32mPATH:\033[0m"
	echo $PATH
}

#####################################################################
# 可疑文件类型检查（如jsp等)
# 在指定目录下检查24h改变的/有777权限的特定类型文件
#####################################################################
function SensitiveFileCheck() {
	echo -e "\n\e[1;34mChecking unusual modules loaded in kernel.\033[0m"
	unusualMod=`lsmod | grep -v "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6ta ble_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4|sb_edac|acpi_cpufreq|ixgbe|pf_ring|tcp_htcp|cfg80211|x86_pkg_temp_thermal|mei_me|mei|processor|thermal_sys|lp|enclosure|ses|ehci_pci|igb|i2c_i801|pps_core|isofs|nls_utf8|xt_REDIRECT|xt_multiport|iosf_mbi|qxl|cdc_ether|usbnet|bluetooth" | grep -v "Module" 2>/dev/null`
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

#####################################################################
# 文件改变检查
#
#####################################################################
function FilesChanged() {
	echo -e "\n\e[1;34mChecking files that are opened but have been deleted.\033[0m"
	# drop the first line
	delFileOpened=`lsof -nP +L1 2>/dev/null| grep '(deleted)' | grep -v 'chrome'`
	while read line; do
		IFS=" "
		tmpArr=($line)
		echo -e "\e[1;33mLow risk. Command: ${tmpArr[0]} PID: ${tmpArr[1]} User: ${tmpArr[2]} File path: ${tmpArr[9]}\033[0m"
	done <<< "$delFileOpened"

	echo -e "\n\e[1;34mChecking files that are changed in 7 days.\033[0m"
	FilesCtime=`find /etc /bin /lib /sbin /dev /root/ /home /tmp /opt /var ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -ctime -7 -type f 2>/dev/null| grep -v "\.log|cache|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n" | xargs -i{} ls -alh {} 2>/dev/null`
	if [[ "$FilesCtime" == "" ]]; then
		echo -e "\e[1;32mNormal. No files changed in 7 days\033[0m"
	else
		while read line; do
			IFS=" "
			tmpArr=($line)
			echo -e "\e[1;33mLow risk. Changed time: ${tmpArr[5]} ${tmpArr[6]} File path: ${tmpArr[8]}\033[0m"
		done <<< "$FilesCtime"
	fi
}

#####################################################################
# 检查使用CPU过多的进程
#
#####################################################################
function ProcAnalyse() {
	echo -e "\n\e[1;34mChecking proc that uses CPU a lot.\033[0m"
	procCPU=`ps -aux 2>/dev/null | grep -v PID | sort -rn -k3 | head | awk '{print $1,$2,$3,$4,$11}' | grep -v 'systemd|rsyslogd|mysqld|redis|apache||nginx|mongodb|docker|memcached|tomcat|jboss|java|php|python'`
	# USER PID percent
	#echo "$procCPU"
	tmpCnt=0
	while read line; do
		IFS=" "
		tmpArr=($line)
		#echo "${tmpArr[2]}"
		# use more than 30% CPU
		if [ `echo "${tmpArr[2]}>30.0" | bc` -eq 1 ]; then
			echo -e "\e[1;33mLow risk. Proc ${tmpArr[1]} uses ${tmpArr[2]}\% CPU \033[0m"
			let tmpCnt++
		fi
	done <<< "$procCPU"
	if [[ $tmpCnt -eq 0 ]]; then
		echo -e "\e[1;32mNormal. No proc that uses CPU a lot found\033[0m"
	fi
}

#####################################################################
# 检查隐藏的process
#
#####################################################################
function HiddenProc() {
	echo -e "\n\e[1;34mCheck hidden processes.\n\033[0m"
	ps -ef | awk '{print}' | sort -n | uniq >tmp1
	ls /proc | sort -n | uniq >tmp2
	diff tmp1 tmp2
	rm tmp1 tmp2
}

#####################################################################
# 检查history
# wget, ssh，ssh brute-force
#####################################################################
function HistoryCheck() {
	echo -e "\n\e[1;34mwget in sh history:\033[0m"
	tmpHistoryWget=`history | grep wget 2>/dev/null`
	if [[ "$tmpHistoryWget" == "" ]]; then
		echo -e "\e[1;32mNormal. No wget history found\033[0m"
	else
		echo -e "$tmpHistoryWget"
	fi

	echo -e "\n\e[1;34mSSH in sh history:\033[0m"
	tmpHistorySSH=`history | grep ssh 2>/dev/null`
	if [[ "$tmpHistorySSH" == "" ]]; then
		echo -e "\e[1;32mNormal. No SSH history found\033[0m"
	else
		echo -e "$tmpHistorySSH"
	fi

	echo -e "\n\e[1;34mChecking ssh login brute-force:\033[0m"
	loginTimes=`lastb | grep root | wc -l`
	#loginTimes=51
	if [ $loginTimes -gt 50 ]; then
		loginIPs=`lastb | grep root | awk '{print $3}' | sort | uniq 2>/dev/null`
		#loginIPs=`echo -e "220.181.38.148"`
		echo -e "\e[1;31mHigh risk. These IPs tried to login as root:\n$loginIPs\033[0m"
		echo -e "\e[0;35mSuggestion: Add unauthorized IPs to blacklist\033[0m"
	else
		echo -e "\e[1;32mNormal. No SSH login brute-force found\033[0m"
	fi
}

#####################################################################
# 检查用户
# 有root权限用户，空口令用户、能登录的user, 所有用户最近一次登录，
# 用户错误登录
#####################################################################
function UserAnalyse() {
	echo -e "\n\e[1;34mChecking user UID=0.\033[0m"
	rootUsers=`awk -F: '{if($3==0)print $1}' /etc/passwd`
	#rootUsers=`echo -e "root\nadmin\nelse"`
	for eachUser in $rootUsers; do
		if [[ "$eachUser" == "root" ]]; then
			echo -e "\e[1;32mNormal. Found root user: $eachUser\033[0m"
		else
			echo -e "\e[1;31mHigh risk. Found root user: $eachUser\033[0m"
		fi
	done

	echo -e "\n\e[1;34mChecking user without password.\033[0m"
	pwUsers=`awk -F: 'length($2)==0 {print $1}' /etc/shadow 2>/dev/null`
	#pwUsers=`echo -e "admin\nelse"`
	#echo "$pwUserss"
	if [[ "$pwUsers" == "" ]]; then
		echo -e "\e[1;32mNormal. Did not find user without password.\033[0m"
	else
		for eachUser in $pwUsers; do
			echo -e "\e[1;31mHigh risk. Found user without password: $eachUser\033[0m"
		done
		echo -e "\e[0;35mSuggestion: Delete the high risk users\033[0m"
	fi

	echo -e "\n\e[1;32mUsers who can log in:\033[0m"
	cat /etc/passwd | grep -E "/bin/bash$"

	echo -e "\n\e[1;32mAll users last log in:\033[0m"
	lastlog
	echo -e "\n\e[1;32mUsers failed to log in:\033[0m"
	sudo lastb
	echo -e "\n\e[1;32mAll users log in and out:\033[0m"
	last -F
}

#####################################################################
# 检查cron
#
#####################################################################
function CronCheck() {
	echo -e "\e[1;32mList cron:\033[0m"
	ls /etc/cron*
}

#####################################################################
# 检查webshell
# 基于文件的webshell检查，目前支持php asp jsp检查
#####################################################################
function WebshellCheck() {
	echo -e "\e[1;32mphp webshell:\033[0m"
	find /var/www/ -name "*.php" |xargs egrep 'assert|phpspy|c99sh|milw0rm|eval|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec|passthru|\(\$\_\POST\[|eval \(str_rot13|\.chr\(|\$\{\"\_P|eval\(\$\_R|file_put_contents\(\.\*\$\_|base64_decode' 2>/dev/null
	find /var/www/ -name "*.php" |xargs egrep '^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php' 2>/dev/null
	find /var/www/ -name "*.php" |xargs egrep '\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))' 2>/dev/null
	find /var/www/ -name "*.php" |xargs egrep '\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))' 2>/dev/null
	find /var/www/ -name "*.php" |xargs egrep "\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?[\'\"]php:\/\/input" 2>/dev/null
	echo -e "\e[1;32masp webshell:\033[0m"
	find /var/www/ -name "*.asp" |xargs egrep '<%@codepage=65000[\s\S]*=936:|<%eval\srequest\(\"|<%@\sPage\sLanguage=\"Jscript\"[\s\S]*eval\(\w+\+|<%@.*eval\(Request\.Item' 2>/dev/null
	echo -e "\e[1;32mjsp webshell:\033[0m"
	find /var/www/ -name "*.jsp" |xargs egrep '<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)' 2>/dev/null
}

#####################################################################
#  create report
#####################################################################
function reportHead() {
	dateStamp=`date "+%s"`

	echo "<!DOCTYPE html>
	<html lang='en' dir='ltr'>
		<head>
			<meta charset='utf-8'>
			<meta name='viewport' content='width=device-width,initial-scale=1'>
			<script src='https://rawgit.com/aFarkas/html5shiv/gh-pages/dist/html5shiv.min.js'></script>
			<link rel='stylesheet' href='normalize.css'>
			<title></title>
		</head>
		<body>" > ./report/${dateStamp}_ER_report.html
}

function reportFoot() {
	dateStamp2Date=`date -d @${dateStamp}`
	echo "<div>$dateStamp2Date</div>
	</body></html>" >> ./report/${dateStamp}_ER_report.html
}

#####################################################################
#  程序开始
#####################################################################

#banner
echo -e "\n\e[1;32m-----------------------------------------------"
echo " ___         __              "
echo "(_    /_ _  / _   _ _ _/'_   "
echo "/__(/((-/  (__)(/(// (//(//) "
echo -e "Welcome to use Euler Guardian!"
echo "This is the emergency response module."
echo -e "-----------------------------------------------\033[0m"

#reportHead

echo -e "\n\e[1;34m\n-----------------------------------------------"
echo "Basic check start"
echo -e "-----------------------------------------------\033[0m\n"
BasicCheck

echo -e "\n\e[1;34m\n-----------------------------------------------"
echo "Files check start"
echo -e "-----------------------------------------------\033[0m\n"
SensitiveFileCheck
FilesChanged

echo -e "\n\e[1;34m\n-----------------------------------------------"
echo "Process check start"
echo -e "-----------------------------------------------\033[0m\n"
ProcAnalyse
HiddenProc

echo -e "\n\e[1;34m\n-----------------------------------------------"
echo "User and log check start"
echo -e "-----------------------------------------------\033[0m\n"
HistoryCheck
UserAnalyse
CronCheck

echo -e "\n\e[1;34m\n-----------------------------------------------"
echo "Webshell check start"
echo -e "-----------------------------------------------\033[0m\n"
WebshellCheck

#reportFoot
