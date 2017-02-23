#! /usr/bin/python

from logging import getLogger, ERROR
getLogger ("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
from datetime import datetime
from time import strftime

import argparse
import re

def checkHostLive(hostaddress):
	conf.verb = 0 #disable any output from scapy itself
	try:
		ping = sr1(IP(dst = hostaddress)/ICMP(), timeout=1) #craft icmp packet
		print("[*] Target is up, Beginning Scan")
	except Exception:
		print("\n[!] Unable to find host!")
		print("[!] Exiting program...")
		sys.exit(1)

def scanThePort(hostaddress, portnumber):
	srcport = RandShort() #pick a random number for the source port
	conf.verb = 0 #disable any output from scapy itself
	SYNACKpkt = sr1(IP(dst = hostaddress)/TCP(sport = srcport, dport = portnumber, flags = 'S'), timeout=4)
	#set the destination, the source port, and destination port. Flag S means SYN packet
	try:
		if SYNACKpkt == None:
			return False
		if TCP in SYNACKpkt:
			return True
		else:
			return False
	except:
		return False
	RSTpkt = IP(dst = hostaddress)/TCP(sport = srcport, dport = portnumber, flags = "R")
	#send the reset packet to close the connection
	send(RSTpkt)

def traceroute(destinationaddress):
	return

parser = argparse.ArgumentParser(description='This is a simple port scanner')
parser.add_argument('-i', '--ipaddress', action="store", required=True, help='Type in IP address of host machine')
parser.add_argument('-p', '--port', action="store", required=True, help='Type in port(s) you wish to scan (use a dash to indicate the range')
args = parser.parse_args()


start_time = datetime.now()
SYNACK = 0x12
RSTACK = 0x14

print("[*] Starting Phillip's Fantastic Port Scanner\n")


#range of ports
portrange = args.port
test = portrange.split("-") #split the string into two numbers
if len(test) > 2:
	print("[!] Please specify a range of ports!")
	print("[!] Exiting program...")
	sys.exit(1)
elif len(test) > 1:
	if test[0] > test[1]: #make sure the number are all good
		print("[!] First port number must be smaller than the second value!")
		print("[!] Exiting program...")
		sys.exit(1)
	portrange = range(int(test[0]), int(test[1])+1) #create a range of numbers to go through
	print(portrange)
	try:
		checkHostLive(args.ipaddress)
		print("[*] Initiated scanning at " + strftime("%H:%M:%S") + "\n")
		for port in portrange:
			status = scanThePort(args.ipaddress, int(port))
			if status == True:
				print("Port " + str(port) + ": Open")
			else:
				print("Port " + str(port) + ": Closed")
	except:
		print("\n[!] Unknown problem detected!")
		print("[!] Exiting program...")
		sys.exit(1)
elif len(test) == 1: #if there is only one number
	checkHostLive(args.ipaddress)
	print("[*] Initiated scanning at " + strftime("%H:%M:%S") + "\n")
	status = scanThePort(args.ipaddress, int(args.port))
	if status == True:
		print("Port " + str(args.port) + ": Open")
	else:
		print("Port " + str(args.port) + ": Closed")
	

end_time = datetime.now()
elapsed_time = end_time - start_time
print("\n[*] Scan Completed")
print("[*] Elapsed Time " + str(elapsed_time))

#http://stackoverflow.com/questions/7541056/pinging-an-ip-range-with-scapy
#http://www.secdev.org/projects/scapy/doc/usage.html
#https://null-byte.wonderhowto.com/how-to/build-stealth-port-scanner-with-scapy-and-python-0164779/
#http://stackoverflow.com/questions/7427101/dead-simple-argparse-example-wanted-1-argument-3-results
