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
	ls -alt /tmp

	echo -e "\e[1;32mServices can be started and stopped manually:\n\033[0m"
	ls -alt /etc/init.d

	echo -e "\e[1;32mPATH:\033[0m"
	echo $PATH
}

#####################################################################
# 可疑文件类型检查（如jsp等)
# 在指定目录下检查24h改变的/有777权限的特定类型文件
#####################################################################
function CertainFileTypeCheck() {
	echo -e "\e[0;36mInput file type e.g.\e[1;35mjsp\e[0;36m or \e[1;35mnext\e[0;36m to execute the next instruction.\033[0m"
	echo -e "\e[1;32mPlease input a type of file:\033[0m"
	read fileType
	while [[ "$fileType" != "next" ]]; do
		echo -e "\e[1;32mPlease input the path you want to check:\033[0m"
		read PathChk
		echo -e "\e[1;32m$fileType files that were changed in 24h \n\033[0m"
		find $PathChk -mtime 0 -name "*.$fileType"
		echo -e "\e[1;32m$fileType files that have 777 perm \n\033[0m"
		find $PathChk *.$fileType -perm 4777
		echo -e "\e[1;32mPlease input a type of file:\033[0m"
		read fileType
	done
	echo -e "\e[1;32mFiles types check finished.\033[0m"
}

#####################################################################
# 文件改变时间检查
# 检查特定目录下、在特定时间改变的文件
#####################################################################
function FilesChangedTime() {
	echo -e "\e[0;36mInput time e.g.\e[1;35mFeb 27\e[0;36m or \e[1;35mnext\e[0;36m to execute the next instruction.\033[0m"
	echo -e "\e[1;32mPlease input month or next:\033[0m"
	read monOfChg
	while [[ "$monOfChg" != "next" ]]; do
		echo -e "\e[1;32mPlease input day:\033[0m"
		read dayOfChg
		timeOfChg=`printf '%s%3i' $monOfChg $dayOfChg`
		echo -e "\e[1;32mPlease input the path you want to check:\033[0m"
		read PathChk
		echo -e "\e[1;32mFiles that were changed on $timeOfChg\n\033[0m"
		ls -al $PathChk | grep "$timeOfChg"
		echo -e "\e[1;32mPlease input month:\033[0m"
		read monOfChg
	done
	echo -e "\e[1;32mFiles changed time check finished.\033[0m"
}

#####################################################################
# 检查网络进程
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
	echo -e "\e[1;32mCheck hidden processes.\n\033[0m"
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
	echo -e "\n\e[1;34mmwget in sh history:\033[0m"
	history | grep wget
	echo -e "\n\e[1;34mssh in sh history:\033[0m"
	history | grep ssh
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
	find /var/www/ -name "*.php" |xargs egrep 'assert|phpspy|c99sh|milw0rm|eval|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec|passthru|\(\$\_\POST\[|eval \(str_rot13|\.chr\(|\$\{\"\_P|eval\(\$\_R|file_put_contents\(\.\*\$\_|base64_decode'
	find /var/www/ -name "*.php" |xargs egrep '^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php'
	find /var/www/ -name "*.php" |xargs egrep '\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))'
	find /var/www/ -name "*.php" |xargs egrep '\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))'
	find /var/www/ -name "*.php" |xargs egrep "\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?[\'\"]php:\/\/input"
	echo -e "\e[1;32masp webshell:\033[0m"
	find /var/www/ -name "*.asp" |xargs egrep '<%@codepage=65000[\s\S]*=936:|<%eval\srequest\(\"|<%@\sPage\sLanguage=\"Jscript\"[\s\S]*eval\(\w+\+|<%@.*eval\(Request\.Item'
	echo -e "\e[1;32mjsp webshell:\033[0m"
	find /var/www/ -name "*.jsp" |xargs egrep '<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)'
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
CertainFileTypeCheck
FilesChangedTime

echo -e "\n\e[1;34m\n-----------------------------------------------"
echo "Net process check start"
echo -e "-----------------------------------------------\033[0m\n"
ProcAnalyse
HiddenProc

echo -e "\n\e[1;34m\n-----------------------------------------------"
echo "History and log check start"
echo -e "-----------------------------------------------\033[0m\n"
HistoryCheck
UserAnalyse
CronCheck

echo -e "\n\e[1;34m\n-----------------------------------------------"
echo "Webshell check start"
echo -e "-----------------------------------------------\033[0m\n"
WebshellCheck

#reportFoot
