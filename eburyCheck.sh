#!/bin/bash

## URL for CERT doc https://www.cert-bund.de/ebury-faq

RED='\033[0;31m'
BLUE='\e[34m'
GREEN='\e[32m'
NC='\033[0m' # No Color

DETECTOS(){
	dist=`grep DISTRIB_ID /etc/*-release | awk -F '=' '{print $2}'`

	if [ "$dist" = "Ubuntu" ]; then
	        os="ubuntu"
	else
	        dist=`cat /etc/*-release | head -1 | awk '{print $1}'`
	        if [ "$dist" = "CentOS" ]; then
	                os="centos"
		else
			if [ "$dist" = "CloudLinux" ]; then
				os="cloudlinux"
			fi
	        fi
	fi
}

## Checks for Ebury version < 1.5 ##

echo -e "++++++++++++++++++++++++++++++++++++++++++++"
echo -e "${BLUE}Checking in Shared Memory Segment for Escalated Permission${NC}"
echo -e "-------------------------------------------------------------"

PERMCOUNT=0
for PERM in `ipcs -m | tail -n +4 | awk '{print $4}'`
do
	#echo -e $PERM
	if [ "$PERM" -gt "600" ]; then
		(( PERMCOUNT++ ))
	fi
done

if [ "$PERMCOUNT" -gt "0" ];then
	echo -e "${RED}ipcs -m command has returned permission value higher than 600. There is possibility for Ebury infection with version < 1.5${NC}"
else
	echo -e "${GREEN}No Problems found for this${NC}"
fi

echo -e "++++++++++++++++++++++++++++++++++++++++++++"

echo -e "${BLUE}Checking in Shared Memory Segment for size greater than 15 kB${NC}"
echo -e "----------------------------------------------------------------"

SIZECOUNT=0
for SIZE in `ipcs -m | tail -n +4 | awk '{print $5}'`
do
	if [ "$SIZE" -gt "15360" ]; then
		(( SIZECOUNT++ ))
	fi
done

if [ "$SIZECOUNT" -gt "0" ];then
	echo -e "${RED}ipcs -m command has returned size greater than 15 kB. There is possibility for Ebury infection with version < 1.3.5${NC}"
else
	echo -e "${GREEN}No Problems found for this${NC}"
fi

echo -e "++++++++++++++++++++++++++++++++++++++++++++"

echo -e "${BLUE}Checking Replacement of the shared library 'libkeyutils' with size greater than 25 kB ${NC}"
echo -e "----------------------------------------------------------------"

LIBKEYUTILSCOUNT=0
for LIBKEYUTILSIZE in `find /lib* -type f -name libkeyutils.so* -exec ls -la {} \; | awk '{print $5}'`
do
	if [ "$LIBKEYUTILSIZE" -gt "25600" ]; then
		(( LIBKEYUTILSCOUNT++ ))
	fi
done

if [ "$LIBKEYUTILSCOUNT" -gt "0" ];then
	echo -e "${RED}libkeyutils found greater than 25 kB resulting in possibility for Ebury infection. Please run this command to check ${GREEN} find /lib* -type f -name libkeyutils.so* -exec ls -la {} \; ${NC}"
else
	echo -e "${GREEN}No Problems found for this${NC}"
fi

echo -e "++++++++++++++++++++++++++++++++++++++++++++"

echo -e "${BLUE}Checking for file libns2.so ${NC}"
echo -e "----------------------------------------------------------------"

LIBNS2COUNT=0
for LIBNS2SIZE in `find /lib* -type f -name libns2.so -exec ls -la {} \; | awk '{print $5}'`
do
	if [ "$LIBNS2SIZE" -gt "0" ]; then
		(( LIBNS2COUNT++ ))
	fi
done

if [ "$LIBNS2COUNT" -gt "0" ];then
	echo -e "${RED}libns2.so file found resulting in possibility for Ebury infection. Please run this command to check ${GREEN} find /lib* -type f -name libns2.so -exec ls -la {} \; ${NC}"
else
	echo -e "${GREEN}No Problems found for this${NC}"
fi

echo -e "++++++++++++++++++++++++++++++++++++++++++++"

echo -e "${BLUE}Checking if interprocess communication is listening on Socket ${NC}"
echo -e "----------------------------------------------------------------"

SOCKETCOUNT=0
for ATD in `netstat -nap | grep '@/proc/udevd' | awk '{print $7}'`
do
		(( SOCKETCOUNT++ ))
done

if [ "$SOCKETCOUNT" -gt "0" ];then
	echo -e "${RED}Ebury infected system found and it is running on socket. Please run this command to check ${GREEN} netstat -nap | grep '@/proc/udevd' ${NC}"
else
	echo -e "${GREEN}No Problems found for this${NC}"
fi

#### Checking for CentOS/CloudLinux specific servers

DETECTOS

echo -e "++++++++++++++++++++++++++++++++++++++++++++"

echo -e "${BLUE}Checking for CentOS/CloudLinux specific servers ${NC}"
echo -e "----------------------------------------------------------------"

if [ "$os" = "centos" ] || [ "$os" = "cloudlinux" ]; then

	LIBPWCOUNT=0
	for LIBPWFILE in `find /lib* -type f -name libpw* -exec ls -la {} \; | awk '{print $9}'`
	do
		if [[ -f $LIBPWFILE ]];then
			if [[ `rpm -qf $LIBPWFILE` == *'not owned'* ]]; then
				echo -e "${RED}Ebury infected. File found $LIBPWFILE ${NC}"
			fi
		fi
		(( LIBPWCOUNT++ ))
	done

	if [ "$LIBPWCOUNT" -gt "0" ];then
		echo -e "${RED}Ebury infected system found with libpw file. Please run this command to check ${GREEN} find /lib* -type f -name libpw* -exec ls -la {} \; ${NC}"
	else
		echo -e "${GREEN}No Problems found for this${NC}"
	fi
	


	if [[ `netstat -pan | grep -w atd` ]]; then
	    printf "This server appears to have atd process listening on Unix socket or network port\nCheck server for possible Ebury infection\n\n===\n`netstat -pan | grep -w atd`\n===\n\n"
	fi

	declare -a file_list=("/lib64/tls/libkeyutils.so.1.5" "/lib64/tls/libkeyutils.so.1" "/lib64/libns2.so" "/lib64/libns5.so" "/lib64/libkeyutils.so.1.3" "/lib64/libpw3.so"); 

	for file in "${file_list[@]}"; do 
	    if [[ -f $file ]]; then
		if [[ `rpm -qf $file` == *'not owned'* ]]; then
		    printf "===\nFile $file is not owned by any RPM package, and there is a possible rootkit infection\nCheck server for possible Ebury infection\n===\n"
		fi
	    fi
	done
fi






