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
# selinux, limitations of resources, password security
####################################################################
function SecCheck() {
	# SElinux
	local SEstatus=`sestatus 2>/dev/null`
	if [ "$SEstatus" ]; then
		echo -e "\e[1;34mSElinux status:\n\033[0m"
		cat /etc/selinux/config | grep SELINUX=
	else
		echo -e "\e[0;36mNo SELinux found.\n\033[0m" 2>/dev/null
	fi

	# limitations of resources
	echo -e "\e[1;34mLimitations for various resources:\n\033[0m"
	ulimit -a

	# password security
	local passMaxDays=`cat /etc/login.defs | grep ^PASS_MAX_DAYS`
	if [ "$passMaxDays" ]; then
		echo -e "\e[1;34mMaximum numbers of days a password may be used:\033[0m${passMaxDays##*[[:space:]]}"
	else
		echo -e "\e[1;34mPASS_MAX_DAYS is not setted.\033[0m"
	fi

	local passMinLen=`cat /etc/login.defs | grep ^PASS_MIN_LEN`
	if [ "$passMinLen" ]; then
		echo -e "\e[1;34mManimum length of a password:\033[0m${passMinLen##*[[:space:]]}"
	else
		echo -e "\e[1;34mPASS_MIN_LEN is not setted.\033[0m"
	fi
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
		echo -e "\e[1;34mHostname:\e[00m\n$Hostname\n\033[0m" 2>/dev/null
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
	echo -e "\e[1;32mFiles permission and ownership check starts...\033[0m"
	echo -e "\e[0;32mIt may take several minutes.\033[0m"

	# all files with "s" perm
	echo -e "\e[1;32m\nFind files have s permission. Please check it in s.txt\033[0m"
	find / -type f -perm -4000 -o -perm -2000 -print 2>/dev/null| xargs ls -al > res/s.txt

	# 777 perm files belonged to nogroup
	echo -e "\e[1;32m\nFind files have 777 perms without group belonged to from root dir:\033[0m"
	find / -perm 777 -nogroup 2>/dev/null

	# orphan files
	echo -e "\e[1;32m\nFind orphan files:\033[0m"
	find / -nouser -o -nogroup 2>/dev/null

	Issue=0
	IssueType=0
	ShowPermissionErr=0 # 1-currently scan is not run by root

	echo -e "\e[0;36m\nPlease input a path to check e.g.\e[1;35m.\e[0;36m or \e[1;35mnext\e[0;36m to execute the next instruction.\033[0m"
	echo -e "\e[0;36mAnd then input the perm you want to check e.g.\e[1;35mr--------\e[0;36m.or \e[1;35mnext\e[0;36m to skip this step.\033[0m"
	echo -e "Defualtly, \e[1;35mrwxrwxrwx\e[0;36m will be checked."
	echo -e "\e[1;32mPlease input a path:\033[0m"
	read FilesPath

	while [[ "$FilesPath" != "next" ]]; do
		echo -e "\e[1;32mPlease input the target permissions:\033[0m"
		read TgtPerm

		for File in ${FilesPath}/*; do
			#echo -e "file: $File\n"
			FilePermission=$(ls -l ${File} | cut -c 2-10)
			#echo -e "perm: $FilePermission"
			GroupPermission=$(ls -l ${File} | cut -c 5-7)
			#echo -e "Gprem: $GroupOwnerId"
			GroupOwnerId=$(ls -n ${File} | awk '{print $4}')
			#echo -e "GOID: $GroupOwnerId"
			Owner=$(ls -l ${File} | awk -F" " '{print $3}')
			#echo -e "Owner: $Owner"
			OwnerId=$(ls -n ${File} | awk -F" " '{print $3}')
			#echo -e "OID: $OwnerId"

			# without TgtPerm, check for files with all rwx perms
			if [ "$TgtPerm" = "next" ]; then
				if [ "${FilePermission}" = "rwxrwxrwx" ]; then
					Issue=1
					IssueType="perms"
					echo -e "\e[1;34m${File} has perms: ${FilePermission}.\033[0m"
				fi

			# check for files perms according to target perms
		elif [[ "${FilePermission}" == "${TgtPerm}" ]];then
				echo -e "\e[1;34m${File} has perms: ${FilePermission}.\033[0m"
				if [[ "${GroupOwnerId}" != "${OwnerId}" ]]; then
					Issue=1;
					IssueType="perms"
					echo -e "\033[0mRecommand to change file perms of ${File} to 640."
				fi
			fi

			#check if it's root user to run scan
			if [ ! "${Owner}" = "root" -a ! "${OwnerId}" = "0" ]; then
				if [ ! "${CurrentId}" = "${OwnerId}" ]; then
					Issue=1
					IssueType="owner"
					ShowPermissionErr=1;
					IssueFile="${File}" #the file with issue
					IssueOwner="${Owner}"
					IssueOwnerId="${OwnerId}"
				fi
			fi

		done
		echo -e "\e[1;32mPlease input a path:\033[0m"
		read FilesPath
	done
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

	targetOVALFile="${releaseNameStr}_${releaseVersionIDStr}.xml"
	#echo "$targetOVALFile"
	hasOVALFile=`ls | grep ${targetOVALFile} 2>/dev/null`
	if [ "$hasOVALFile" ]; then
		echo -e "\e[1;34mOVAL file found:\e[00m\n$targetOVALFile\n\033[0m" 2>/dev/null
	else
		echo -e "\e[0;36mNo target OVALFile found. Downloading...\n\033[0m" 2>/dev/null
		wget -q https://oval.cisecurity.org/repository/download/5.11.2/vulnerability/${targetOVALFile}
		hasOVALFile=`ls | grep ${targetOVALFile} 2>/dev/null`
		if [ "$hasOVALFile" ]; then
			:
			#echo "has oval file"
		else
			wget -q https://oval.cisecurity.org/repository/download/5.11.2/vulnerability/centos_linux_73.xml
			targetOVALFile="centos_linux_73.xml"
		fi
	fi

	oscap oval eval --results ./oscap_results.xml --report ./report/oscap_report.html ${targetOVALFile}
	echo -e "\e[1;34mPlease check for vuln scan results in oscap_results.xml and oscap_report.html\n\033[0m" 2>/dev/null
}


########################################################################
# log auditing
########################################################################
function LogAudit() {
:
}


#####################################################################
# Function
# Function [functionName] [var1 var2 ...]
#####################################################################
function Function {
	functionName=$1 #第一个参数，函数名
	shift 1 #参数左移1
	args=$@ #每个参数
	${functionName} ${args} #执行function, 格式为函数名 参数
	if [[ "$?" -eq 0 ]]; then #执行function退出状态不出错
		echo -e ${functionName} ${args} "\e[0;32mCheck passed. \033[0m"
	else
		echo -e ${functionName} ${args} "\e[0;31mCheck failed. \033[0m"
	fi
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
		<body>" > ./report/${timeStamp}_EG_report.html
}

function ReportFoot() {
	timeStamp2Date=`date -d @${timeStamp}`
	echo "<div>$timeStamp2Date</div>
	</body></html>" >> ./report/${timeStamp}_EG_report.html
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

echo -e "\e[1;34m-----------------------------------------------"
echo "System information check start"
echo -e "-----------------------------------------------\033[0m"
PreOp
SysInfoChk
SecCheck

echo -e "\e[1;34m-----------------------------------------------"
echo "Users information check start"
echo -e "-----------------------------------------------\033[0m"
UserInfoChk

echo -e "\e[1;34m-----------------------------------------------"
echo "Files permissions check start"
echo -e "-----------------------------------------------\033[0m"
FilePermChk

echo -e "\e[1;34m-----------------------------------------------"
echo "Software vuln check start"
echo -e "-----------------------------------------------\033[0m"
OVALChk
