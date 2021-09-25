##########################################################################
# File Name: download-oval.sh
# Author: Anaïs Huang
# mail: anaishuangc0conut@gmail.com
# Created Time: Sat 25 Sep 2021 08:18:06 PM CST
#########################################################################
#!/bin/bash
# download oval files and turn into
# fmt: ${releaseNameStr}${releaseVersionIDStr}.oval.xml

#rhel 6-8
for (( i = 6; i < 9; i++ )); do
	wget https://www.redhat.com/security/data/oval/v2/RHEL${i}/rhel-${i}.oval.xml.bz2
	bunzip2 rhel-${i}.oval.xml.bz2
	mv rhel-${i}.oval.xml rhel${i}.oval.xml
done

# ubuntu
wget https://security-metadata.canonical.com/oval/com.ubuntu.$(lsb_release -cs).usn.oval.xml.bz2
bunzip2 com.ubuntu.$(lsb_release -cs).usn.oval.xml.bz2
mv com.ubuntu.$(lsb_release -cs).usn.oval.xml ubuntu.oval.xml

rm *.bz2
