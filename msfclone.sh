#!/bin/bash

# This is an unattended version of https://gist.github.com/4393324
# You must have rights to the /opt dir, which usually means root.

MSFENV=/opt/metasploit*/scripts/setenv.sh
if [ -f $MSFENV ];
then
	source $MSFENV
fi
rm -rf /opt/metasploit/msf3 
mkdir -p /opt/metasploit/msf3
\curl -LO http://curl.haxx.se/ca/cacert.pem
CURL_CA_BUNDLE=$PWD/cacert.pem \curl -L http://r-7.co/UsEqxW > msfclone.rb
MSFBASE=/opt/metasploit/msf3 MSFUNATTENDED=true ruby msfclone.rb


