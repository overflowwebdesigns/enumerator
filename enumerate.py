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

print "Looking for low hanging fruit hang on..."
time.sleep(20)
print "Still lookin, patience young padewan..."

IP = sys.argv[1] # IP address
os.system("mkdir /root/Desktop/"+IP) # Creates a directory on your Desktop
nm = nmap.PortScanner() # Initialize Nmap module
nm.scan(IP, '80,443,22,21,139,445') # Target ports
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

print "*" * 10
print "Beginning Service Scan of all ports... Your pwnage can begin soon..."
print "*" * 10
os.system("nmap -sV -p- -v -T4 -oN /root/Desktop/"+IP+"/service_scan.txt "+IP) # Full TCP scan of all 65535 ports
