##########################################################################
# File Name: config.sh
# Author: Anaïs Huang
# mail: anaishuangc0conut@gmail.com
# Created Time: Sat 09 Oct 2021 04:45:47 PM CST
# Please run this file before using Euler Guardian
#########################################################################
#!/bin/bash

echo -e "\e[1;32m-----------------------------------------------"
echo " ___         __              "
echo "(_    /_ _  / _   _ _ _/'_   "
echo "/__(/((-/  (__)(/(// (//(//) "
echo -e "Welcome to use Euler Guardian!"
echo "The configuration process start!"
echo -e "-----------------------------------------------\033[0m"

# install oscap for local scan module
if [ "$(oscap -h 2>/dev/null)" ]; then
	echo -e "\e[1;32moscap found.\n\033[0m"
elif [ "$(apt -v 2>/dev/null)" ]; then
	echo -e "\e[1;34mNo oscap. Downloading using apt...\n\033[0m"
	apt-get install libopenscap8
	if [ "$(oscap -h 2>/dev/null)" ]; then
		echo -e "\e[1;32mDone.\n\033[0m"
	else
		echo -e "\e[1;31mCould not install oscap. Please check your internet connection.\nExit.\n\033[0m"
		exit
	fi
elif [ "$(yum --version 2>/dev/null)" ]; then
	echo -e "\e[1;34mNo oscap. Downloading using yum...\n\033[0m"
	yum install openscap-utils -y
	if [ "$(oscap -h 2>/dev/null)" ]; then
		echo -e "\e[1;32mDone.\n\033[0m"
	else
		echo -e "\e[1;31mCould not install oscap. Please check your internet connection.\nExit.\n\033[0m"
		exit
	fi
fi

# install ssmtp to send emails
if [ "$(man sendmail 2>/dev/null)" ]; then
	echo -e "\e[1;32mssmtp found.\n\033[0m"
elif [ "$(apt -v 2>/dev/null)" ]; then
	echo -e "\e[1;34mNo sendmail. Downloading...\n\033[0m"
	apt-get install ssmtp
	if [ "$(man sendmail 2>/dev/null)" ]; then
		echo -e "\e[1;32mDone.\n\033[0m"
	else
		echo -e "\e[1;31mCould not install ssmtp. Please check your internet connection.\nExit.\n\033[0m"
		exit
	fi
elif [ "$(yum --version 2>/dev/null)" ]; then
	echo -e "\e[1;34mNo sendmail. Downloading...\n\033[0m"
	yum install ssmtp
	if [ "$(man sendmail 2>/dev/null)" ]; then
		echo -e "\e[1;32mDone.\n\033[0m"
	else
		echo -e "\e[1;31mCould not install ssmtp. Please check your internet connection.\nExit.\n\033[0m"
		exit
	fi
fi
