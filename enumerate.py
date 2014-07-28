#!/bin/python
import sys
import os

IP = sys.argv[1] # IP address
init_nmap = 'nmap -T5 -p- -o'+IP+'.txt'+' '+IP
os.system(init_nmap)

port_file = open(IP+'.txt', r)
ports = port_file.readlines()
for target in ports:
	if target == "80 open":
		print "80 open"
	

