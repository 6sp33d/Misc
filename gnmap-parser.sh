#!/bin/bash

#============================================================================
#  Gnmap-Parser.sh | [Version]: 1.0 | [Updated]: 10.28.2022
#============================================================================

# Global Variables
parsedir=Parsed-Results
portldir=${parsedir}/Port-Lists
portfdir=${parsedir}/Port-Files
portmdir=${parsedir}/Port-Matrix
hostldir=${parsedir}/Host-Lists
hosttype=${parsedir}/Host-Type
thrdprty=${parsedir}/Third-Party
ipsorter='sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'


# Gather Gnmap Files Function
func_gather(){
  # Begin Gathering Gnmap Files Normally
  echo '[*] Gathering .gnmap Files'
  find ${floc} -name *.gnmap -exec cp {} . \; >>/dev/null 2>&1
  gathered=$(ls *|grep ".gnmap"|wc -l)
  #echo "[*] Gathered ${gathered} .gnmap Files"
  # Validation Checks For Gathered Gnmap Files
  if [ ${gathered} -gt '0' ]; then
    func_parse
  else
    exit 0
  fi
}

# Function To Parse .gnmap Files
func_parse(){
  # Check For .gnmap Files Before Parsing
  fcheck=$(ls|grep ".gnmap"|wc -l)
  if [ "${fcheck}" -lt '1' ]; then
    echo '[!] Failed: No Gnmap Files Found (*.gnmap)'
    echo
    echo '--[ Possible Fixes ]--'
    echo
    echo '[1] If all of your gnmap files have the correct extension, use option (-g).'
    echo '[2] If some of your gnmap files dont have the extension, use option (-gg).'
    echo '[3] Place this script in a directory with all relevant *.gnmap files.'
    echo
    exit 1
  fi

  # Create Parsing Directories If Non-Existent
  # Preparing Directories
  for dir in ${parsedir} ${portldir} ${portfdir} ${portmdir} ${hostldir} ${hosttype} ${thrdprty}; do
    if [ ! -d ${dir} ]; then
        mkdir ${dir}
    fi
  done

  echo '[*] Parsing .gnmap files'
  
  # Build Alive Hosts Lists
  awk '!/^#|Status: Down/' *.gnmap|sed -e 's/Host: //g' -e 's/ (.*//g'|${ipsorter} > ${hostldir}/Alive-Hosts-ICMP.txt
  awk '!/^#/' *.gnmap|grep "open/"|sed -e 's/Host: //g' -e 's/ (.*//g'|${ipsorter} > ${hostldir}/Alive-Hosts-Open-Ports.txt

  # Build Host-Type Lists
  #echo '[*] Building Host-Type Windows List'
  WINRULE01=$(grep "445/open/tcp" *.gnmap|grep -v "22/open/tcp"|cut -d" " -f2)
  WINRULE02=$(grep "135/open/tcp" *.gnmap|grep -v "445/open/tcp"| cut -d" " -f2)
  WINRULE03=$(grep "445/open/tcp" *.gnmap|grep "3389/open/tcp"|cut -d" " -f2)
  #echo ${WINRULE01} ${WINRULE02} ${WINRULE03}|tr ' ' '\n'|${ipsorter} > ${hosttype}/Windows.txt
  
  #echo '[*] Building Host-Type UNIX/Linux List'
  NIXRULE01=$(grep "22/open/tcp" *.gnmap|grep -v "23/open/tcp"|cut -d" " -f2)
  NIXRULE02=$(grep "111/open/tcp" *.gnmap|grep -v "445/open/tcp"|cut -d" " -f2)
  #echo ${NIXRULE01} ${NIXRULE02}|tr ' ' '\n'|${ipsorter} > ${hosttype}/Nix.txt

  #echo '[*] Building Host-Type Webservers List'
  WEBRULE01=$(grep "80/open/tcp" *.gnmap|cut -d" " -f2)
  WEBRULE02=$(grep "443/open/tcp" *.gnmap|cut -d" " -f2)
  #echo ${WEBRULE01} ${WEBRULE02}|tr ' ' '\n'|${ipsorter} > ${hosttype}/Webservers.txt

  #echo '[*] Building Host-Type Network Devices List'
  NETRULE01=$(grep "80/open/tcp" *.gnmap|grep "23/open/tcp"|grep "22/open/tcp"|grep -v "445/open/tcp"|cut -d" " -f2)
  #echo ${NETRULE01}|tr ' ' '\n'|${ipsorter} > ${hosttype}/Network-Devices.txt

  #echo '[*] Building Host-Type Printers List'
  PRNRULE01=$(grep "80/open/tcp" *.gnmap|grep "23/open/tcp"|grep "22/open/tcp"|grep "445/open/tcp"|cut -d" " -f2)
  PRNRULE02=$(grep "1900/open/tcp" *.gnmap|cut -d" " -f2)
  #echo ${PRNRULE01}|tr ' ' '\n'|${ipsorter} > ${hosttype}/Printers.txt

  # Build TCP Ports List
  #echo '[*] Building TCP Ports List'
  grep "Ports:" *.gnmap|sed -e 's/^.*Ports: //g' -e 's;/, ;\n;g'|awk '!/udp/'|grep 'open'|cut -d"/" -f 1|sort -n -u > ${portldir}/TCP-Ports-List.txt

  # Build UDP Ports List
  #echo '[*] Building UDP Ports List'
  grep "Ports:" *.gnmap|sed -e 's/^.*Ports: //g' -e 's;/, ;\n;g'|awk '!/tcp/'|grep '/open/'|cut -d"/" -f 1|sort -n -u > ${portldir}/UDP-Ports-List.txt

  # Build TCP Port Files
  for port in $(cat ${portldir}/TCP-Ports-List.txt); do
    TCPPORT="${port}"
    #echo '[*] Building TCP Port Files'
    #echo "The Current TCP Port Is: ${TCPPORT}"
    WHAT=$(cat /usr/share/nmap/nmap-services |  tr -s "/" " "  | tr '\t' ' ' | cut -d" " -f1,2,3 | grep -i tcp | grep -w $TCPPORT | cut -d" " -f1)
    cat *.gnmap|grep " ${TCPPORT}/open/tcp"|sed -e 's/Host: //g' -e 's/ (.*//g'|${ipsorter} > ${portfdir}/${TCPPORT}-"$WHAT"-TCP.txt
  done

  # Build UDP Port Files
  for port in $(cat ${portldir}/UDP-Ports-List.txt); do
    UDPPORT="${port}"
    #echo '[*] Building UDP Port Files'
    #echo "The Current UDP Port Is: ${UDPPORT}"
    cat *.gnmap|grep " ${UDPPORT}/open/udp"|sed -e 's/Host: //g' -e 's/ (.*//g'|${ipsorter} > ${portfdir}/${UDPPORT}-UDP.txt
  done

  # Remove Stale Matrices
  for p in TCP UDP; do
    if [ -f ${portmdir}/${p}-Services-Matrix.csv ]; then
      #echo "[*] Removing Stale ${p} Matrix"
      rm ${portmdir}/${p}-Services-Matrix.csv
    fi
  done

  # Build TCP Services Matrix
  for port in $(cat ${portldir}/TCP-Ports-List.txt); do
    TCPPORT="${port}"
    #echo '[*] Building TCP Services Matrix'
    #echo "The Current TCP Port Is: ${TCPPORT}"
    cat *.gnmap|grep " ${port}/open/tcp"|sed -e 's/Host: //g' -e 's/ (.*//g' -e "s/$/,TCP,${port}/g"|${ipsorter} >> ${portmdir}/TCP-Services-Matrix.csv
  done

  # Build UDP Services Matrix
  for port in $(cat ${portldir}/UDP-Ports-List.txt); do
    UDPPORT="${port}"
    #echo '[*] Building UDP Services Matrix'
    #echo "The Current UDP Port Is: ${UDPPORT}"
    cat *.gnmap|grep " ${port}/open/udp"|sed -e 's/Host: //g' -e 's/ (.*//g' -e "s/$/,UDP,${port}/g"|${ipsorter} >> ${portmdir}/UDP-Services-Matrix.csv
  done

  # Remove Stale PeepingTom File
  if [ -f ${thrdprty}/PeepingTom.txt ]; then
    #echo '[*] Removing Stale PeepingTom.txt'
    rm ${thrdprty}/PeepingTom.txt
  fi

  # Build PeepingTom Input File
  for i in $(cat ${portldir}/TCP-Ports-List.txt); do
    TCPPORT="${i}"
    #echo '[*] Building PeepingTom Input File'
    #echo "The Current TCP Port Is: ${TCPPORT}"
    cat *.gnmap|grep " ${i}/open/tcp//http/\| ${i}/open/tcp//http-alt/\| ${i}/open/tcp//http?/\| ${i}/open/tcp//http-proxy/\| ${i}/open/tcp//appserv-http/"|\
         sed -e 's/Host: //g' -e 's/ (.*//g' -e "s.^.http://.g" -e "s/$/:${i}/g"|${ipsorter} >> ${thrdprty}/PeepingTom.txt
    cat *.gnmap|grep " ${i}/open/tcp//https/\| ${i}/open/tcp//https-alt/\| ${i}/open/tcp//https?/\| ${i}/open/tcp//ssl|http/"|\
         sed -e 's/Host: //g' -e 's/ (.*//g' -e "s.^.https://.g" -e "s/$/:${i}/g"|${ipsorter} >> ${thrdprty}/PeepingTom.txt
  done

  # Remove Empty Files
  #echo '[*] Removing Empty Files'
  find ${parsedir} -size 0b -exec rm {} \;
  find ${parsedir} -size 1c -exec rm {} \;

  # Show Complete Message
  echo '[*] Parsing Complete'
}

# Start Statement
case ${1} in
  -g)
    func_gather ${2}
    ;;
  -p|--parse)
    func_parse
    ;;
  *)
    echo " Usage...: ${0} [OPTION]"
    echo ' Options.:'
    echo '           -p  = Parse .gnmap Files'
    echo '           -h  = Show This Help'
esac


exit
