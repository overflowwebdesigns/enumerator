#### Install python Nmap module http://xael.org/norman/python/python-nmap/
####
####
####
####
#### Usage: ./enumerate.py <ip address>
####
####

#!/bin/python
import sys
import os
import nmap
import time

print "Scanning standby..."
time.sleep(10)
print "Still Scanning..."

IP = sys.argv[1] # IP address
nm = nmap.PortScanner() # Initialize Nmap module
nm.scan(IP, '80,443,22,21') # Target ports
nm.command_line()
nm.scaninfo()
	

for host in nm.all_hosts():
	print('--------------------')
	print('Host: %s (%s)' % (IP, nm[host].hostname()))
	print('State: %s' % nm[host].state())
	print('--------------------')

for proto in nm[host].all_protocols():
	print('--------------------')
	print('Protocol: %s' % proto)

lport = nm[host]['tcp'].keys()
lport.sort()
for port in lport:
	print('--------------------')
	print('port: %s\tstate: %s' % (port, nm[host][proto][port]['state']))
	print('--------------------')
