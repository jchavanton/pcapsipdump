#!/bin/bash

if [ "$1" = "" ]; then
	CMD="tail -f /dev/null"
else
	CMD="$*"
fi

# cd /src && svn checkout https://svn.code.sf.net/p/pcapsipdump/code/trunk pcapsipdump-code
# cd /src/pcapsipdump-code && make && make install

# /usr/sbin/pcapsipdump -v 9 -r /files/michael_2025-03-12T14_34_47-05_00.pcap
# 20250312-193453-+17276106264-+14253728514-8f42c1d5-be4c1123-e781a1d9-2e4040a5.pcap

# /usr/sbin/pcapsipdump -v 1 -f -r /files/michael_2025-03-12T14_34_47-05_00.pcap  -m "^(INVITE)$"

echo "Running ${CMD}"
exec ${CMD}
