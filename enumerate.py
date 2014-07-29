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
import ftplib

print "Looking for low hanging fruit hang on..."
time.sleep(20)
print "Still lookin, patience young padewan..."

IP = sys.argv[1] # IP address
os.system("mkdir /root/Desktop/"+IP) # Creates a directory on your Desktop
nm = nmap.PortScanner() # Initialize Nmap module
nm.scan(IP, '80,443,22,21,139,445') # Target ports
nm.command_line()
nm.scaninfo()

###########################
def ftp(): # Attempts to login to FTP using anonymous user
	try:
		ftp_info = open('/root/Desktop/'+IP+"ftp_info.txt",'w')
		ftp = ftplib.FTP(IP)
		ftp.login()
		print "\o/"
		print "FTP ALLOWS ANONYMOUS ACCESS!"
		print "o/\o"
		print "*" * 10
		ftp.quit()
	except:
		print "FTP does not allow anonymous access :("
############################

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

if nm[host].has_tcp(21):
		print "*" * 10
		print "FTP FOUND - CHECKING FOR ANONYMOUS ACCESS"
		ftp()
		
print "#" * 10
print "Beginning Service Scan of all ports... Your pwnage can begin soon..."
print "#" * 10
os.system("nmap -sV -p- -v -T4 -oN /root/Desktop/"+IP+"/service_scan.txt "+IP) # Full TCP scan of all 65535 ports
