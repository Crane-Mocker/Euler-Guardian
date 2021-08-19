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
# 1.current id check，check if current id has root perms
# 2.check SetUID, get pwd
# 3.check if there are results files left from previous scan,
# if so, delete them
#######################################################################
function PreOp() {
	local CurrentId=""
	if [ -x /usr/xpg4/bin/id ]; then #Solaris
		CurrentId=$(/usr/xpg4/bin/id -u 2>/dev/null)
	elif [ "$(uname)" = "SunOS" ]; then
		CurrentId=$(id | tr '=' ' ' | tr '(' ' ' | awk '{ print $2 }' 2>/dev/null)
	else #"$(uname)" = "Linux", for Euler, ubuntu, etc
		CurrentId=$(id -u 2>/dev/null)
	fi

	#check if UID = 0(root)
	if [ ${CurrentId} -eq 0 ]; then
		IsRoot=1
		ScanMode=0
	else
		IsRoot=0
		ScanMode=1
	fi

	#check SetUID ("s")
	if [ -u "$0" ]; then
		echo -e "\e[0;36mStopped because of unusual SetUID. Exit.\n\033[0m"
		exit 1
	fi
	WorkDir=$(pwd)

	rm oscap* s.txt 2>/dev/null
}

########################################################################
# system info check
# kernel info, detailed kernel info, release info
########################################################################
function SysInfoChk() {
	# kernel info
	local UnameInfo=`uname -a 2>/dev/null`	#`uname -a`
	if [ "$UnameInfo" ]; then
		# standard output and add to $report
		echo -e "\e[1;34mKernel info:\e[00m\n$UnameInfo\n\033[0m" |tee -a $report 2>/dev/null
	else
		echo -e "\e[0;36mUname failed.\n\033[0m" |tee -a $report 2>/dev/null
	fi

	# kernel version, gcc version to compile, time of compilation
	local KernelVersion=`cat /proc/version 2>/dev/null`
	if [ "$KernelVersion" ]; then
		echo -e "\e[1;34mKernel version:\e[00m\n$KernelVersion\n\033[0m" |tee -a $report 2>/dev/null
	else
		echo -e "\e[0;36mcat /proc/version failed.\n\033[0m"|tee -a $report 2>/dev/null
	fi

	#release info
	local ReleaseInfo=`cat /etc/*-release 2>/dev/null`
	if [ "$ReleaseInfo" ]; then
		echo -e "\e[1;34mrelease info:\e[00m\n$ReleaseInfo\n\033[0m" |tee -a $report 2>/dev/null
	else
		echo -e "\e[0;36mcat /etc/*-release failed.\n\033[0m"|tee -a $report 2>/dev/null
	fi
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
		echo -e "\e[0;36mNo SELinux found.\n\033[0m"|tee -a $report 2>/dev/null
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
		echo -e "\e[1;34mHostname:\e[00m\n$Hostname\n\033[0m" |tee -a $report 2>/dev/null
	else
		echo -e "\e[0;36mhostname failed.\n\033[0m"|tee -a $report 2>/dev/null
	fi

	#id
	local Id=`id 2>/dev/null`
	if [ "$Id" ]; then
		echo -e "\e[1;34mCurrent user and group IDs:\e[00m\n$Id\n\033[0m" |tee -a $report 2>/dev/null
	else
		echo -e "\e[0;36mid failed.\n\033[0m"|tee -a $report 2>/dev/null
	fi

	#user accounts info
	local Passwd=`cat /etc/passwd | cut -d ":" -f 1,2,3,4 2>/dev/null`
	if [ "$Passwd" ]; then
		echo -e "\e[1;34mUsers and permissions:\033[0m"
		echo -e "\e[0;34mUsername:Password:UID:GID\033[0m"
		echo -e "\e[00m$Passwd\n\033[0m" |tee -a $report 2>/dev/null
		#group memebership
		local GroupIdInfo=`for i in $(cat /etc/passwd 2>/dev/null| cut -d":" -f1 2>/dev/null);do id $i;done 2>/dev/null`
		if [ "$GroupIdInfo" ]; then
			echo -e "\e[1;34mGroup memberships:\e[00m\n$GroupIdInfo\n\033[0m" |tee -a $report 2>/dev/null
		else
			:
		fi
		#if password stored in /etc/passwd as hash
		local HashPw=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
		if [ "$HashPw" ]; then
			echo -e "\e[1;34mFound password stored in /etc/passwd as hash:\n\033[0m$HashPw\n" | tee -a $report 2>/dev/null
		else
			echo -e "\e[0;34mNo password is stored in /etc/passwd as hash.\n\033[0m" |tee -a $report 2>/dev/null
		fi
	else
		echo -e "\e[0;36m cat /etc/passwd failed.\n\033[0m" |tee -a $report 2>/dev/null
	fi

	#last log for each user
	local LastLogUser=`lastlog 2>/dev/null | grep -v "Never"`
	if [ "$LastLogUser" ]; then
		echo -e "\e[1;34mUsers previously logged onto system:\e[0m\n$LastLogUser\n\033[0m" |tee -a $report 2>/dev/null
	else
		echo -e "\e[0;36mCan't find /var/log/lastlog.\n\033[0m"|tee -a $report 2>/dev/null
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
	find / -type f -perm -4000 -o -perm -2000 -print 2>/dev/null| xargs ls -al > s.txt

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
		echo -e "\e[1;34mThis device uses apt.\n\033[0m" |tee -a $report 2>/dev/null
		# if oscap is installed
		if [ "$(oscap -h 2>/dev/null)" ]; then
			:
		else
			echo -e "\e[1;34mNo oscap. Downloading...\n\033[0m" |tee -a $report 2>/dev/null
			sudo apt-get install libopenscap8
		fi
	elif [ "$(yum --version 2>/dev/null)" ]; then
		# use yum
		echo -e "\e[1;34mThis device uses yum.\n\033[0m" |tee -a $report 2>/dev/null

		# if oscap is installed
		if [ "$(oscap -h 2>/dev/null)" ]; then
			:
		else
			echo -e "\e[1;34mNo oscap. Downloading...\n\033[0m" |tee -a $report 2>/dev/null
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
		echo -e "\e[1;34mOVAL file found:\e[00m\n$targetOVALFile\n\033[0m" |tee -a $report 2>/dev/null
	else
		echo -e "\e[0;36mNo target OVALFile found. Downloading...\n\033[0m" |tee -a $report 2>/dev/null
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

	oscap oval eval --results ./oscap_results.xml --report ./oscap_report.html ${targetOVALFile}
	echo -e "\e[1;34mPlease check for vuln scan results in oscap_results.xml and oscap_report.html\n\033[0m" |tee -a $report 2>/dev/null
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

###################################################################
# myFunction
###################################################################

#function myFunction() {
#	local myLocalVar=
#	:
#}

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

echo -e "\e[1;34m\n-----------------------------------------------"
echo "System information check start"
echo -e "-----------------------------------------------\033[0m\n"
PreOp
SysInfoChk
SecCheck

echo -e "\e[1;34m\n-----------------------------------------------"
echo "Users information check start"
echo -e "-----------------------------------------------\033[0m\n"
UserInfoChk

echo -e "\e[1;34m\n-----------------------------------------------"
echo "Files permissions check start"
echo -e "-----------------------------------------------\033[0m\n"
FilePermChk

echo -e "\e[1;34m\n-----------------------------------------------"
echo "Software vuln check start"
echo -e "-----------------------------------------------\033[0m\n"
OVALChk
