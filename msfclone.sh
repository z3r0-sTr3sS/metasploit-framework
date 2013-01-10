#!/bin/bash

# This is an unattended version of https://gist.github.com/4393324
# You must have rights to the /opt dir, which usually means root.

MSFENV=/opt/metasploit*/scripts/setenv.sh
if [ -f $MSFENV ];
then
	source $MSFENV
	MSFBASE=dirname $MSFENV
else
        MSFBASE=/opt/metasploit/msf3
fi
rm -rf $MSFBASE
mkdir -p $MSFBASE 
\curl -LO http://curl.haxx.se/ca/cacert.pem
CURL_CA_BUNDLE=$PWD/cacert.pem \curl -L http://r-7.co/UsEqxW > msfclone.rb
MSFUNATTENDED=true ruby msfclone.rb

