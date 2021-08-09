##########################################################################
# File Name: local-scan.sh
# Author: Anaïs Huang
# mail: anaishuangc0conut@gmail.com
# Created Time: Mon 28 Jun 2021 09:16:21 AM CST
#########################################################################
#!/bin/sh

#PROGRAM_NAME="EG_local_scan"
#PROGRAM_AUTHOR="c0conut"

#banner
echo -e "\e[1;32m---------------------------------------\n"
echo -e "Welcome to use Euler Guardian!\n"
echo -e "---------------------------------------\n\033[0m"

#######################################################################
# check current id
#######################################################################

#check current id
CurrentId=""
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

#####################################################################
#path
#####################################################################
#check SetUID ("s")
if [ -u "$0" ]; then
	echo -e "\e[0;36mStopped because of unusual SetUID. Exit.\n\033[0m"
	exit 1
fi

#pwd
WorkDir=$(pwd)

########################################################################
# system info
########################################################################
echo -e "\e[1;32mSystem information check starts...\n\033[0m"

# kernel info
UnameInfo=`uname -a 2>/dev/null`	#`uname -a`
if [ "$UnameInfo" ]; then
	# standard output and add to $report
	echo -e "\e[1;34mKernel info:\e[00m\n$UnameInfo\n\033[0m" |tee -a $report 2>/dev/null
else
	echo -e "\e[0;36mUname failed.\n\033[0m" |tee -a $report 2>/dev/null
fi

# kernel version, gcc version to compile, time of compilation
KernelVersion=`cat /proc/version 2>/dev/null`
if [ "$KernelVersion" ]; then
	echo -e "\e[1;34mKernel version:\e[00m\n$KernelVersion\n\033[0m" |tee -a $report 2>/dev/null
else
	echo -e "\e[0;36mcat /proc/version failed.\n\033[0m"|tee -a $report 2>/dev/null
fi

#release info
ReleaseInfo=`cat /etc/*-release 2>/dev/null`
if [ "$ReleaseInfo" ]; then
	echo -e "\e[1;34mrelease info:\e[00m\n$ReleaseInfo\n\033[0m" |tee -a $report 2>/dev/null
else
	echo -e "\e[0;36mcat /etc/*-release failed.\n\033[0m"|tee -a $report 2>/dev/null
fi


########################################################################
# user info
########################################################################
echo -e "\e[1;32mUser information check starts...\n\033[0m"

# hostname
Hostname=`hostname 2>/dev/null`
if [ "$Hostname" ]; then
	echo -e "\e[1;34mHostname:\e[00m\n$Hostname\n\033[0m" |tee -a $report 2>/dev/null
else
	echo -e "\e[0;36mhostname failed.\n\033[0m"|tee -a $report 2>/dev/null
fi

#id
Id=`id 2>/dev/null`
if [ "$Id" ]; then
	echo -e "\e[1;34mCurrent user and group IDs:\e[00m\n$Id\n\033[0m" |tee -a $report 2>/dev/null
else
	echo -e "\e[0;36mid failed.\n\033[0m"|tee -a $report 2>/dev/null
fi

#user accounts info
Passwd=`cat /etc/passwd | cut -d ":" -f 1,2,3,4 2>/dev/null`
if [ "$Passwd" ]; then
	echo -e "\e[1;34mUsers and permissions:\033[0m"
	echo -e "\e[0;34mUsername:Password:UID:GID\033[0m"
	echo -e "\e[00m$Passwd\n\033[0m" |tee -a $report 2>/dev/null
	#group memebership
	GroupIdInfo=`for i in $(cat /etc/passwd 2>/dev/null| cut -d":" -f1 2>/dev/null);do id $i;done 2>/dev/null`
	if [ "$GroupIdInfo" ]; then
		echo -e "\e[1;34mGroup memberships:\e[00m\n$GroupIdInfo\n\033[0m" |tee -a $report 2>/dev/null
	else
		:
	fi
	#if password stored in /etc/passwd as hash
	HashPw=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
	if [ "$HashPw" ]; then
		echo -e "\e[1;34mFound password stored in /etc/passwd as hash:\n\033[0m$HashPw\n" | tee -a $report 2>/dev/null
	else
		echo -e "\e[0;34mNo password is stored in /etc/passwd as hash.\n\033[0m" |tee -a $report 2>/dev/null
	fi
else
	echo -e "\e[0;36m cat /etc/passwd failed.\n\033[0m" |tee -a $report 2>/dev/null
fi

#last log for each user
LastLogUser=`lastlog | grep -v "Never" 2>/dev/null`
if [ "$LastLogUser" ]; then
	echo -e "\e[1;34mUsers previously logged onto system:\e[0m\n$LastLogUser\n\033[0m" |tee -a $report 2>/dev/null
else
	echo -e "\e[0;36mCan't find /var/log/lastlog.\n\033[0m"|tee -a $report 2>/dev/null
fi

#######################################################################
#file permission/ownership check
#######################################################################
echo -e "\e[1;32mFiles permission and ownership check starts...\033[0m"

FilesPath="consts functions"
Issue=0
IssueType=0
ShowPermissionErr=0 # 1-currently scan is not run by root
IncludeDir="" #with bash files to do tests



for File in ${FilesPath}; do
	FilePermission=$(ls -l ${IncludeDir}/${File} | cut -c 2-10)
	GroupPermission=$(ls -l ${IncludeDir}/${File} | cut -c 5-7)
	GroupOwnerId=$(ls -n ${IncludeDir}/${File} | awk '{print $4}')
	Owner=$(ls -l ${IncludeDir}/${File} | awk -F" " '{print $3}')
	OwnerId=$(ls -n ${IncludeDir}/${File} | awk -F" " '{print $3}')
	#check permissions of include files
	#for files has alll rwx
	if [ "${FilePermission}" = "rwxrwxrwx" ]; then
		Issue=1
		IssueType="perms"
		echo -e "\e[1;34mChange file permissions of ${IncludeDir}/${File} to 640.\033[0m"
		#echo "Command: chmod 640 ${IncludeDir}/${File}"
	#if group owner id=owner id, consider it as defualt umask
	elif [ ! "${FilePermission}"="r--------" -a ! "${FilePermission}"="rw-------"-a!"${FilePermission}"="rw-r-----" -a ! "${FilePermission}"="rw-r--r--" ];then
		if [ ! "${GroupOwnerId}" = "${OwnerId}" ]; then
			Issue=1;
			IssueType="perms"
			echo -e "\033[0mChange file permissions of ${IncludeDir}/${File} to 640."
		fi
	fi

	#check if it's root user to run scan
	if [ ! "${Owner}" = "root" -a ! "${OwnerId}" = "0" ]; then
		if [ ! "${CurrentId}" = "${OwnerId}"]; then
			Issue=1
			IssueType="owner"
			ShowPermissionErr=1;
			IssueFile="${File}" #the file with issue
			IssueOwner="${Owner}"
			IssueOwnerId="${OwnerId}"
		fi
	fi
done

#if scan isn't run by Root
if [ ${ShowPermissionErr} -eq 1 ]; then
	print "%s" "

[!] Change ownership of ${IncludeDir}/${IssueFile} to 'root' or similar (found: ${IssueOwner} with UID ${IssueOwnerId}).

Command:
  # chown 0:0 ${IncludeDir}/${IssueFile}
"
fi

####################################################################
# 软件包版本漏洞检查
####################################################################

# 检查使用的包管理器, 安装oscap
if [ "$(apt -v 2>/dev/null)" ]; then
	#使用apt作为包管理器
	echo -e "\e[1;34mThis device uses apt.\n\033[0m" |tee -a $report 2>/dev/null
	# 检查是否有oscap工具
	if [ "$(oscap -h 2>/dev/null)" ]; then
		:
	else
		echo -e "\e[1;34mNo oscap. Downloading...\n\033[0m" |tee -a $report 2>/dev/null
		sudo apt-get install libopenscap8
	fi
elif [ "$(yum --version 2>/dev/null)" ]; then
	# 使用yum作为包管理器
	echo -e "\e[1;34mThis device uses yum.\n\033[0m" |tee -a $report 2>/dev/null

	# 检查是否有oscap工具
	if [ "$(oscap -h 2>/dev/null)" ]; then
		:
	else
		echo -e "\e[1;34mNo oscap. Downloading...\n\033[0m" |tee -a $report 2>/dev/null
		sudo yum install openscap-utils
	fi
fi

# 检查oval文件
# release id
tmpStr=`cat /etc/*-release | grep ^ID=`
IFS='='
read -ra tmpArr <<<"$tmpStr"
releaseIDStr=${tmpArr[1]}
#echo "$releaseIDStr"

# release version id
tmpStr=`cat /etc/*-release | grep VERSION_ID 2>/dev/null`
IFS='"'
read -ra tmpArr <<<"$tmpStr"
releaseVersionID=${tmpArr[1]}
releaseVersionIDStr=`echo ${releaseVersionID//./}`
#echo "$releaseVersionIDStr"

targetOVALFile="${releaseIDStr}_${releaseVersionIDStr}.xml"
#echo "$targetOVALFile"
hasOVALFile=`ls | grep ${targetOVALFile} 2>/dev/null`
if [ "$hasOVALFile" ]; then
	echo -e "\e[1;34mOVAL file found:\e[00m\n$targetOVALFile\n\033[0m" |tee -a $report 2>/dev/null
else
	echo -e "\e[0;36mNo target OVALFile found. Downloading...\n\033[0m" |tee -a $report 2>/dev/null
	wget https://oval.cisecurity.org/repository/download/5.11.2/vulnerability/${targetOVALFile}
	hasOVALFile=`ls | grep ${targetOVALFile} 2>/dev/null`
	if [ "hasOVALFile" ]; then
		:
	else
		wget https://oval.cisecurity.org/repository/download/5.11.2/vulnerability/centos_linux_73.xml
		targetOVALFile="centos_linux_73.xml"
	fi
fi

oscap oval eval --results ./oscap_results.xml --report ./oscap_report.html ${targetOVALFile}
echo -e "\e[1;34mPlease check for vuln scan results in oscap_results.xml and oscap_report.html\n\033[0m" |tee -a $report 2>/dev/null

########################################################################
# log auditing
########################################################################



########################################################################
# config file check
########################################################################


####################################################################
# 函数调用部分
####################################################################

#####################################################################
# 常量
#####################################################################
FSTAB='/etc/fstab'
GRUB_CFG='/boot/grub/grub.cfg' #/boot/grub2/grub.cfg
GRUB_DIR='/etc/grub.d'

#####################################################################
# 函数调用
# Function [functionName函数名] [对应函数的参数]
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

######################################################################
# 挂载选项
# nodev: 在挂载时添加nodev选项，系统不会把该fs的block/character文件
# 当作是block/character文件来处理。
# nosuid: 阻止suid和sgid位的操作
# noexec: 该挂载点的文件不允许运行(即使有x权限)
# MountOption [filesystem挂载点对应的文件系统] [mountOption挂载选项]
#####################################################################

function MountOption {
	local filesystem="${1}"
	local mountOption="${2}"
	#执行命令，失败则return
	grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" | grep -q "${mountOption}" || return
	mount | greo "[[:space:]]${filesystem}[[:space:]]" | grep -q "${mountOption}" || return
}

####################################################################
# selinux检查
####################################################################
function SELinuxCheck {
	#if SElinux is disabled in grub.cfg selinux=0关闭
	local SelinuxEq0="$(grep selinux=0 ${GRUB_CFG})"
	[[ -z "${SelinuxEq0}" ]] || return
	local enforcingEq0="$(grep enforcing=0 $(GRUB_CFG))"
	[[ -z "${enforcingEq0}" ]] || return
}

###################################################################
# 自定义函数
###################################################################

#function myFunction {
#	local myLocalVar=
#	:
#}

####################################################################
# 主函数
####################################################################
function main {
	:
}
