##########################################################################
# File Name: local-scan.sh
# Author: Anaïs Huang
# mail: anaishuangc0conut@gmail.com
# Created Time: Mon 28 Jun 2021 09:16:21 AM CST
#########################################################################
#!/bin/sh

#PROGRAM_NAME="local_scan"
#PROGRAM_AUTHOR="c0conut"

# results of scan
scanRes=()
# risk level of each scan
riskLevel=()

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

	rm res/s.txt 2>/dev/null
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

	kernelName=`uname -s 2>/dev/null`
	kernelRelease=`uname -r 2>/dev/null`
	echo -e "\e[1;34mKernel:\033[0m $kernelName $kernelRelease"
	hardwareP=`uname -i`
	echo -e "\e[1;34mPlatform:\033[0m $hardwareP"

	echo "<div class='each-part'>
		<h2><a href='#system-information' name='system-information'>System Information</a></h2>
		<p>OS: ${releaseNameStr} ${releaseVersionID}</p>
		<p>Kernel: ${kernelName} ${kernelRelease}</p>
		<p>Platform: ${hardwareP}</p>
	" >> ./report/EG_report_${timeStamp}.html
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
		local tmpStr=`cat /etc/selinux/config | grep SELINUX=`
		echo "$tmpStr"
		scanRes[${#scanRes[*]}]="Found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
		SELinux status:</br>
		</span>
		${tmpStr}</p>
		" >> ./report/EG_report_${timeStamp}.html
	else
		echo -e "\e[1;33mLow risk. SELinux not found\033[0m"
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="low"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/low.png) no-repeat;'>
		SELinux not found
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	fi

	# limitations of resources
	echo -e "\n\e[1;34mLimitations for various resources:\033[0m"
	ulimit -a
	tmpStr=`ulimit -a`
	scanRes[${#scanRes[*]}]=`ulimit -a | wc -l`
	riskLevel[${#riskLevel[*]}]="normal"
	echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
	Limitations for various resources:
	</span>
	</br>
	${tmpStr}
	</p>
	" >> ./report/EG_report_${timeStamp}.html
}

#######################################################################
# audit system check
#
#######################################################################
function AuditChk() {
	if [ "$(apt -v 2>/dev/null)" ]; then
		if [ "$(auditd 2>/dev/null)" ]; then
			scanRes[${#scanRes[*]}]="Found"
			riskLevel[${#riskLevel[*]}]="normal"
			echo -e "\e[1;32mNormal. Linux Auditing System found.\033[0m"
			echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
			Linux Auditing System found
			</span></p>
			" >> ./report/EG_report_${timeStamp}.html
		else
			scanRes[${#scanRes[*]}]="Not found"
			riskLevel[${#riskLevel[*]}]="low"
			echo -e "\e[1;33mLow risk. No Linux Auditing System\033[0m"
			echo "<p><span style='padding-left: 19px; background: url(../template/pic/low.png) no-repeat;'>
			No Linux Auditing System
			</span></p>
			" >> ./report/EG_report_${timeStamp}.html
		fi
	elif [ "$(yum --version 2>/dev/null)" ]; then
		if [ "$(yum list audit audit-libs 2>/dev/null | grep audit)" ]; then
			scanRes[${#scanRes[*]}]="Found"
			riskLevel[${#riskLevel[*]}]="normal"
			echo -e "\e[1;32mNormal. Linux Auditing System found.\033[0m"
			echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
			Linux Auditing System found
			</span></p>
			" >> ./report/EG_report_${timeStamp}.html
		else
			scanRes[${#scanRes[*]}]="Not found"
			riskLevel[${#riskLevel[*]}]="low"
			echo -e "\e[1;33mLow risk. No Linux Auditing System\033[0m"
			echo "<p><span style='padding-left: 19px; background: url(../template/pic/low.png) no-repeat;'>
			No Linux Auditing System
			</span></p>
			" >> ./report/EG_report_${timeStamp}.html
		fi
	fi

	echo "</div>" >> ./report/EG_report_${timeStamp}.html
}

########################################################################
# user info
# hostname, id, user accounts info, if passwords are stored as hash,
# last login
########################################################################
function UserInfoChk() {
	echo "<div class='each-part'>
		<h2><a href='#user-information' name='user-information'>User Information</a></h2>" >> ./report/EG_report_${timeStamp}.html

	# hostname
	Hostname=`hostname 2>/dev/null`
	if [ "$Hostname" ]; then
		echo -e "\e[1;34mHostname: \e[00m$Hostname\n\033[0m" 2>/dev/null
		echo "<p>Hostname: ${Hostname}
		</p>" >> ./report/EG_report_${timeStamp}.html
	else
		echo -e "\e[0;36mhostname failed.\n\033[0m" 2>/dev/null
	fi

	#id
	local Id=`id 2>/dev/null`
	if [ "$Id" ]; then
		scanRes[${#scanRes[*]}]=`id | grep -oE ^uid=[0-9]*`
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;34mCurrent user and group IDs:\e[00m\n$Id\n\033[0m" 2>/dev/null
		echo -e "<p>Current user and group IDs:
		</br>
		${Id}
		</p>" >> ./report/EG_report_${timeStamp}.html
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
		riskLevel[${#riskLevel[*]}]="normal"
		if [ "$HashPw" ]; then
			scanRes[${#scanRes[*]}]="Yes"
			echo -e "\e[1;34mFound password stored in /etc/passwd as hash:\n\033[0m$HashPw\n" 2>/dev/null
			echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
			Found password stored in /etc/passwd as hash.
			</span>
			</p>" >> ./report/EG_report_${timeStamp}.html
		else
			scanRes[${#scanRes[*]}]="No"
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

	echo "</div>" >> ./report/EG_report_${timeStamp}.html
}

########################################################################
# user identity
# hostname, id, user accounts info, if passwords are stored as hash,
# last login
########################################################################
function UserIdenChk() {
	echo "<div class='each-part'>
		<h2><a href='#user-iden' name='user-iden'>User identity and access control</a></h2>" >> ./report/EG_report_${timeStamp}.html

	# basic password configuration
	local pwMaxDay=`cat /etc/login.defs | grep ^PASS 2>/dev/null | grep PASS_MAX_DAYS 2>/dev/null| egrep ^[0-9]`
	local pwMinDay=`cat /etc/login.defs | grep ^PASS 2>/dev/null | grep PASS_MIN_DAYS 2>/dev/null| egrep ^[0-9]`
	local pwMinLen=`cat /etc/login.defs | grep ^PASS 2>/dev/null | grep PASS_MIN_LEN 2>/dev/null| egrep ^[0-9]`
	local pwWarnAge=`cat /etc/login.defs | grep ^PASS 2>/dev/null | grep PASS_WARN_AGE 2>/dev/null| egrep ^[0-9]`

	local riskFlag=0 # normal

	if [[ "$pwMaxDay" == "" ]] || [[ $pwMaxDay -eq 99999 ]]; then
		riskFlag=1
		echo -e "\e[1;33mLow risk. No limitation of password expired days\033[0m"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/low.png) no-repeat;'>
		No limitation of password expired days
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	else
		echo -e "\e[1;32mNormal.\e[1;34mDays for a password to expire:\033[0m $pwMaxDay"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
		Days for a password to expire: ${pwMaxDay}
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	fi

	if [[ "$pwMinDay" == "" ]]; then
		riskFlag=1
		echo -e "\e[1;33mLow risk. No limitation of days to wait after last change of password\033[0m"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/low.png) no-repeat;'>
		No limitation of days to wait after last change of password
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	else
		echo -e "\e[1;32mNormal.\e[1;34mMin days to wait after last change of password:\033[0m $pwMinDay"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
		Min days to wait after last change of password: ${pwMinDay}
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	fi

	if [[ "$pwMinLen" == "" ]]; then
		riskFlag=1
		echo -e "\e[1;33mLow risk. No limitation of password min length\033[0m"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/low.png) no-repeat;'>
		No limitation of password min length
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	else
		echo -e "\e[1;32mNormal.\e[1;34mMin length of password:\033[0m $pwMinLen"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
		Min length of password: ${pwMinLen}
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	fi

	if [[ "$pwWarnAge" == "" ]]; then
		riskFlag=1
		echo -e "\e[1;33mLow risk. Did not set a date to get warning before password expiration\033[0m"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/low.png) no-repeat;'>
		Did not set a date to get warning before password expiration
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	else
		echo -e "\e[1;32mNormal.\e[1;34mDays to receive warning before password expiration:\033[0m $pwWarnAge"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
		Days to receive warning before password expiration: ${pwWarnAge}
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	fi

	if [ $riskFlag -eq 0 ]; then #normal
		scanRes[${#scanRes[*]}]="Normal"
		riskLevel[${#riskLevel[*]}]="normal"
	else
		scanRes[${#scanRes[*]}]="Low risk"
		riskLevel[${#riskLevel[*]}]="low"
	fi

	#pam password config
	local pamCracklib=`cat /etc/pam.d/system-auth 2>/dev/null | grep pam_cracklib.so 2>/dev/null`
	if [[ "$pamCracklib" == "" ]]; then
		scanRes[${#scanRes[*]}]="Cracklib not found"
		riskLevel[${#riskLevel[*]}]="low"
		echo -e "\e[1;33mLow risk. Cracklib not found"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/low.png) no-repeat;'>
		Cracklib not found
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
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
		scanRes[${#scanRes[*]}]="Normal"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. Cracklib found.\033[0m"
		echo -e "\e[0;32mRetry times: $pamRetry\tMin num of different chars: $pamDifok\nMin length of password: $pamMinLen\tMin num of upper case chars: $pamUcredit\nMin num of lower case chars: $pamLcredit\tMin num of numbers: $pamDcredit\nPassword dictionary path: $pamDictPath\033[0m"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
		Cracklib found.
		</span></p>
		<p>Retry times: ${pamRetry} </br>
		Min num of different chars: ${pamDifok} </br>
		Min length of password: ${pamMinLen} </br>
		Min num of upper case chars: ${pamUcredit} </br>
		Min num of lower case chars: ${pamLcredit} </br>
		Min num of numbers: ${pamDcredit} </br>
		Password dictionary path: ${pamDictPath}
		</p>
		" >> ./report/EG_report_${timeStamp}.html
	fi

	# user without password
	echo -e "\n\e[1;34mChecking user without password.\033[0m"
	local pwUsers=`awk -F: 'length($2)==0 {print $1}' /etc/shadow 2>/dev/null`
	if [[ "$pwUsers" == "" ]]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. Did not find user without password.\033[0m"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
		Did not find user without password
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	else
		scanRes[${#scanRes[*]}]="Found"
		riskLevel[${#riskLevel[*]}]="high"
		for eachUser in $pwUsers; do
			echo -e "\e[1;31mHigh risk. Found user without password: $eachUser\033[0m"
			echo "<p><span style='padding-left: 19px; background: url(../template/pic/high.png) no-repeat;'>
			Found user without password: ${eachUser}
			</span></p>
			" >> ./report/EG_report_${timeStamp}.html
		done
		echo -e "\e[0;35mSuggestion: Delete the high risk users\033[0m"
	fi

	echo "</div>" >> ./report/EG_report_${timeStamp}.html
}

#######################################################################
# file check
#
#######################################################################
function FileChk() {
	echo "<div class='each-part'>
		<h2><a href='#files-check' name='files-check'>Files Check</a></h2>
	" >> ./report/EG_report_${timeStamp}.html

	# all files with "s" perm
	echo -e "\e[1;34mChecking files which have s permission"
	echo -e "\e[0;34mIt may take several minutes.\033[0m"
	find / -type f -perm -4000 -o -perm -2000 -print 2>/dev/null| xargs ls -al > res/s.txt
	# s.txt size != 0
	if [ $(du -b res/s.txt | grep -oE ^[0-9]*) -ne 0 ]; then
		scanRes[${#scanRes[*]}]="Found"
		riskLevel[${#riskLevel[*]}]="low"
		echo -e "\e[1;33mLow risk. Files with s perm found. Please check them in res/s.txt\033[0m"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/low.png) no-repeat;'>
		Files with s perm found. Please check them in res/s.txt
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	# s.txt size == 0
	else
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. No files with s perm found\033[0m"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
		No files with s perm found
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	fi

	# 777 perm files belonged to nogroup
	echo -e "\n\e[1;34mChecking files have 777 perms without group belonged to\033[0m"
	file777Perm=`find / -perm 777 -nogroup 2>/dev/null`
	if [[ "$file777Perm" == "" ]]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. No files having 777 perm without group belonged to\033[0m"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
		No files having 777 perm without group belonged to
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	else
		scanRes[${#scanRes[*]}]="Found"
		riskLevel[${#riskLevel[*]}]="high"
		echo -e "\e[1;31mHigh risk. Found:\n\033[0m$file777Perm"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/high.png) no-repeat;'>
		Found files having 777 perm without group belonged to:
		</span>
		</br>
		${file777Perm}
		</p>
		" >> ./report/EG_report_${timeStamp}.html
	fi

	# orphan files
	echo -e "\n\e[1;34mChecking orphan files\033[0m"
	orphanFile=`find / -nouser -o -nogroup 2>/dev/null`
	if [[ "$orphanFile" == "" ]]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. No orphan file found\033[0m"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
		No orphan file found
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	else
		scanRes[${#scanRes[*]}]="Found"
		riskLevel[${#riskLevel[*]}]="high"
		echo -e "\e[1;31mHigh risk. Found:\n\033[0m$orphanFile"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/high.png) no-repeat;'>
		Found orphan files:
		</span>
		</br>
		${orphanFile}
		</p>
		" >> ./report/EG_report_${timeStamp}.html
	fi

	echo -e "\n\e[1;34mChecking unusual modules loaded in kernel.\033[0m"
	unusualMod=`lsmod | egrep -v "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6ta ble_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4|sb_edac|acpi_cpufreq|ixgbe|pf_ring|tcp_htcp|cfg80211|x86_pkg_temp_thermal|mei_me|mei|processor|thermal_sys|lp|enclosure|ses|ehci_pci|igb|i2c_i801|pps_core|isofs|nls_utf8|xt_REDIRECT|xt_multiport|iosf_mbi|qxl|cdc_ether|usbnet|bluetooth" 2>/dev/null`
	if [[ "$unusualMod" == "" ]]; then
		scanRes[${#scanRes[*]}]="Not found"
		riskLevel[${#riskLevel[*]}]="normal"
		echo -e "\e[1;32mNormal. No unusual module found\033[0m"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/normal.png) no-repeat;'>
		No unusual module found
		</span></p>
		" >> ./report/EG_report_${timeStamp}.html
	else
		scanRes[${#scanRes[*]}]="Found"
		riskLevel[${#riskLevel[*]}]="high"
		echo "<p><span style='padding-left: 19px; background: url(../template/pic/high.png) no-repeat;'>
		Found unusual modules:
		</span>
		</br>
		" >> ./report/EG_report_${timeStamp}.html
		while read line; do
			IFS=" "
			tmpArr=($line)
			echo -e "\e[1;33mLow risk. Module: ${tmpArr[0]}\033[0m"
			echo "Module: ${tmpArr[0]} </br>" >> ./report/EG_report_${timeStamp}.html
		done <<< "$unusualMod"
		echo "</p>" >> ./report/EG_report_${timeStamp}.html
	fi

	echo "</div>" >> ./report/EG_report_${timeStamp}.html
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

	echo -e "\e[1;34mPlease check the reports in report dir\033[0m" 2>/dev/null

	echo "<div class='each-part'>
		<h2><a href='sec_conf_${timeStamp}.html'>Security Configuration Scan</a></h2>
	</div>
	" >> ./report/EG_report_${timeStamp}.html
	echo "<div class='each-part'>
		<h2><a href='comp_vuln_${timeStamp}.html'>OVAL Scan</a></h2>
	</div>
	" >> ./report/EG_report_${timeStamp}.html
}

#####################################################################
#  create report
#####################################################################
function ReportHead() {

	echo "<!DOCTYPE html>
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
		<body>" > ./report/EG_report_${timeStamp}.html
}

function ReportFoot() {
	timeStamp2Date=`date -d @${timeStamp}`
	echo -e "</body></html>" >> ./report/EG_report_${timeStamp}.html
}

function ReportSum() {
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
			<h2><a href='#'>System Information</a></h2>
			<table>
				<tbody>
					<tr>
						<td>OS</td>
						<td>${releaseNameStr} ${releaseVersionID}</td>
					</tr>
					<tr>
						<td>Kernel</td>
						<td>${kernelName} ${kernelRelease}</td>
					</tr>
					<tr>
						<td>Platform</td>
						<td>${hardwareP}</td>
					</tr>
					<tr>
						<td>SELinux</td>
						<td>
							<a href='./EG_report_${timeStamp}.html#system-information'>
							<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[0]}.png) no-repeat;'>
								${scanRes[0]}
							</span>
							</a>
						</td>
					</tr>
					<tr>
						<td>Limitations for various resources</td>
						<td>
							<a href='./EG_report_${timeStamp}.html#system-information'>
							<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[1]}.png) no-repeat;'>
								${scanRes[1]} items
							</span>
							</a>
						</td>
					</tr>
					<tr>
						<td>Linux Auditing System</td>
						<td>
							<a href='./EG_report_${timeStamp}.html#system-information'>
							<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[2]}.png) no-repeat;'>
								${scanRes[2]}
							</span>
							</a>
						</td>
					</tr>
				</tbody>
			</table>
	</div>

	<div class='each-part'>
			<h2><a href='#'>User Information</a></h2>
			<table>
				<tbody>
					<tr>
						<td>Hostname</td>
						<td>${Hostname}</td>
					</tr>
					<tr>
						<td>Current UID</td>
						<td>
							<a href='./EG_report_${timeStamp}.html#user-information'>
								${scanRes[3]}
							</a>
						</td>
					</tr>
					<tr>
						<td>Found passwords in /etc/passwd stored as hash</td>
						<td>
							<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[4]}.png) no-repeat;'>
								${scanRes[4]}
							</span>
						</td>
					</tr>
				</tbody>
			</table>
	</div>

	<div class='each-part'>
			<h2><a href='#'>User identity and access control</a></h2>
			<table>
				<tbody>
					<tr>
						<td>basic password configuration</td>
						<td>
							<a href='./EG_report_${timeStamp}.html#user-iden'>
								<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[5]}.png) no-repeat;'>
									${scanRes[5]}
								</span>
							</a>
						</td>
					</tr>
					<tr>
						<td>pam Cracklib configuration</td>
						<td>
							<a href='./EG_report_${timeStamp}.html#user-iden'>
								<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[6]}.png) no-repeat;'>
									${scanRes[6]}
								</span>
							</a>
						</td>
					</tr>
					<tr>
						<td>User without password</td>
						<td>
							<a href='./EG_report_${timeStamp}.html#user-iden'>
								<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[7]}.png) no-repeat;'>
									${scanRes[7]}
								</span>
							</a>
						</td>
					</tr>
				</tbody>
			</table>
	</div>

	<div class='each-part'>
			<h2><a href='#'>Files Check</a></h2>
			<table>
				<tbody>
					<tr>
						<td>File(s) with S perm</td>
						<td>
							<a href='../res/s.txt'>
								<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[8]}.png) no-repeat;'>
									${scanRes[8]}
								</span>
							</a>
						</td>
					</tr>
					<tr>
						<td>777 perm file(s) without group belonged to</td>
						<td>
							<a href='./EG_report_${timeStamp}.html#files-check'>
								<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[9]}.png) no-repeat;'>
									${scanRes[9]}
								</span>
							</a>
						</td>
					</tr>
					<tr>
						<td>orphan file(s)</td>
						<td>
							<a href='./EG_report_${timeStamp}.html#files-check'>
								<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[10]}.png) no-repeat;'>
									${scanRes[10]}
								</span>
							</a>
						</td>
					</tr>
					<tr>
						<td>Unusual kernel module(s)</td>
						<td>
							<a href='./EG_report_${timeStamp}.html#files-check'>
								<span style='padding-left: 19px; background: url(../template/pic/${riskLevel[11]}.png) no-repeat;'>
									${scanRes[11]}
								</span>
							</a>
						</td>
					</tr>
				</tbody>
			</table>
	</div>

	<div class='each-part'>
			<h2><a href='sec_conf_${timeStamp}.html'>Security Configuration Scan</a></h2>
	</div>

	<div class='each-part'>
			<h2><a href='comp_vuln_${timeStamp}.html'>OVAL Scan</a></h2>
	</div>

	</body></html>
	" > ./report/EG_index_${timeStamp}.html
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
ReportHead
SysInfoChk
SecCheck
AuditChk

echo -e "\n\e[1;34m-----------------------------------------------"
echo "Users information and access control check"
echo -e "-----------------------------------------------\033[0m"
UserInfoChk
UserIdenChk

echo -e "\n\e[1;34m-----------------------------------------------"
echo "Files check"
echo -e "-----------------------------------------------\033[0m"
FileChk

echo -e "\n\e[1;34m-----------------------------------------------"
echo "Software vuln check"
echo -e "-----------------------------------------------\033[0m"
OVALChk

echo -e "\n\e[1;34m-----------------------------------------------"
echo "Generating reports"
echo -e "-----------------------------------------------\033[0m"
ReportFoot
ReportSum
