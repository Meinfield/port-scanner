#! /usr/bin/python

from logging import getLogger, ERROR
getLogger ("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
from datetime import datetime
from time import strftime

import argparse

import signal
import sys
def signal_handler(signal, frame):
        print('[1] Closing Program Due to User Interrupt!')
        sys.exit(0)


def checkHostLive(hostaddress):
	conf.verb = 0 #disable any output from scapy itself
	try:
		ping = sr1(IP(dst = hostaddress)/ICMP(), timeout=1) #craft icmp packet
		print("[*] Target is up, Beginning Scan")
	except Exception:
		print("\n[!] Unable to find host!")
		print("[!] Exiting program...")
		sys.exit(1)

def TCPscanThePort(hostaddress, portnumber):
	srcport = RandShort() #pick a random number for the source port
	conf.verb = 0 #disable any output from scapy itself
	SYNACKpkt = sr1(IP(dst = hostaddress)/TCP(sport = srcport, dport = portnumber, flags = 'S'), timeout=10)
	#set the destination, the source port, and destination port. Flag S means SYN packet
	print("hey")
	print(SYNACKpkt.getlayer(TCP).flags)
	try:
		if SYNACKpkt is None:
			return False
		if SYNACKpkt.getlayer(TCP).flags == 0x12:
			return True
		else:
			return False
	except:
		return False
	RSTpkt = IP(dst = hostaddress)/TCP(sport = srcport, dport = portnumber, flags = "R")
	#send the reset packet to close the connection
	send(RSTpkt)

def UDPscanThePort(hostaddress, portnumber):
	dst_timeout=5
	udp_scan_resp = sr1(IP(dst=hostaddress)/UDP(dport=portnumber),timeout=dst_timeout)
	try:
		if udp_scan_resp is None:
			return False
		if UDP in udp_scan_resp:
			return True
		else:
			return False
	except:
		return False

def ICMPscan(hostaddress, portnumber):
	ping = sr1(IP(dst = hostaddress)/ICMP(dport=portnumber), timeout=1) #craft icmp packet
	try:
		if ping is None:
			return False
		else:
			return True
	except:
		print("\n[!] Unable to find host!")
		print("[!] Exiting program...")
	sys.exit(1)

def traceroute(destinationaddress):
	hostname = "google.com"
	for i in range(1, 28):
		pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)# Send the packet and get a reply
		reply = sr1(pkt, verbose=0)
		if reply is None:
			break
		elif reply.type == 3:
			print("Done!", reply.src)
			break
		else:
			print("%d hops away: " % i , reply.src)
	# try:
	# 	for hopnumber in range (1,30):
	# 		#send and receive packet using a random, probably closed port
	# 		replypkt = sr1(IP(dst=destinationaddress, ttl=hopnumber)/UDP(dport=22222), timeout=2, verbose=0)
	# 		if replypkt is None:
	# 			break
	# 		elif replypkt.type == 3:
	# 			print("[*] Reached Destination ", replypkt.src)
	# 		else:
	# 			print(" %d: " %hopnumber, replypkt.src)
	# 	sys.exit(1)
	# except:
	# 	print("\n[!] Unknown problem detected!")
	# 	print("[!] Exiting program...")
	# 	sys.exit(1)

	# flag = True
	# ttl=1
	# hops = []
	# while flag and ttl!=25:
	# 	ans, unans = sr(IP(dst=destinationaddress,ttl=ttl)/UDP(dport=22222), timeout=3)
	# 	print(ans.res[0][1].type)
	# 	if ans.res[0][1].type == 0x12: # checking for  ICMP echo-reply
	# 		flag = False
	# 		print("help")
	# 		print(hops)
	# 	else:
	# 		hops.append(ans.res[0][1].src) # storing the src ip from ICMP error message
	# 		print(hops)
	# 		ttl +=1
	# i = 1
	# for hop in hops:
	# 	print(i, " ", hop)
	# 	i+=1
	# sys.exit(1)

	# ans,unans=sr(IP(dst=destinationaddress, ttl=(1,25))/TCP(flags=0x2))
	# try:
	# 	for snd,rcv in ans:
	# 		print(" " + snd.ttl + " Address: " + rcv.src)
	# except:
	# 	for snd,rcv in ans:
	# 		print(" ", snd.ttl, " Address: ", rcv.src)
	# 	print("\n[!] Unknown problem detected!")
	# 	print("[!] Exiting program...")
	# 	sys.exit(1)
	# sys.exit(1)

def initiatePortScan(ip):
	#range of ports
	try:
		portrange = args.port
		portlist = portrange.split("-") #split the string into two numbers
		if len(portlist) > 2:
			print("[!] Please correctly specify a range of ports!")
			print("[!] Exiting program...")
			sys.exit(1)
		elif len(portlist) > 1:
			if portlist[0] > portlist[1]: #make sure the number are all good
				print("[!] First port number must be smaller than the second value!")
				print("[!] Exiting program...")
				sys.exit(1)
			portrange = range(int(portlist[0]), int(portlist[1])+1) #create a range of numbers to go through
			try:
				checkHostLive(ip)
				print("[*] Initiated scanning at " + strftime("%H:%M:%S") + "\n")
				for port in portrange:
					if str(args.protocol) == "UDP":
						status = UDPscanThePort(ip, int(port))
					else:
						status = TCPscanThePort(ip, int(port))

					if status == True:
						print("Port " + str(port) + ": Open")
					else:
						print("Port " + str(port) + ": Closed")
					return
			except:
				print("\n[!] Unknown problem detected!")
				print("[!] Exiting program...")
				sys.exit(1)
		elif len(portlist) == 1: #if there is only one number
			checkHostLive(ip)
			print("[*] Initiated scanning at " + strftime("%H:%M:%S") + "\n")
			if str(args.protocol) == "UDP":
				status = UDPscanThePort(ip, int(args.port))
			else:
				status = TCPscanThePort(ip, int(args.port))

			if status == True:
				print("Port " + str(args.port) + ": Open")
			else:
				print("Port " + str(args.port) + ": Closed")
			return
	except:
		#no port specified
		for port in range(1,101):
			if str(args.protocol) == "UDP":
				status = UDPscanThePort(ip, int(port))
			else:
				print('sdhk')
				status = TCPscanThePort(ip, int(port))
			if status == True:
				print("Port " + str(port) + ": Open")
			else:
				print("Port " + str(port) + ": Closed")

parser = argparse.ArgumentParser(description='This is a simple port scanner')
parser.add_argument('-i', '--ipaddress', action="store", help='Type in IP address of host machine; Type in multiple hosts by adding a "-<last host\'final two digits>"')
parser.add_argument('-p', '--port', action="store", help='Type in port(s) you wish to scan (use a dash to indicate the range), default is ports 1 -100')
parser.add_argument('-t', '--traceroute', action="store", help='Type in IP address you wish to get a route to')
parser.add_argument('-u', '--protocol', action="store", help='Type in UDP or TCP after, default is TCP')

args = parser.parse_args()

start_time = datetime.now()
SYNACK = 0x12
RSTACK = 0x14

signal.signal(signal.SIGINT, signal_handler)

print("[*] Starting Phillip's Fantastic Port Scanner\n")

#check for if anything is possbile
if args.traceroute is None and args.ipaddress is None:
	print("[!] Please insert a correct argument, type '-h' or '--help' for assistance")
	sys.exit(1);

#check for traceroute
if args.traceroute is not None:
	traceroute(args.traceroute)

#range of ip addresses
iprange = args.ipaddress
iplist = iprange.split("-") #split the string into two numbers
try:
	if len(iplist) > 2:
		print("[!] Please correctly specify a range of hosts!")
		print("[!] Exiting program...")
		sys.exit(1)
	elif len(iplist) > 1:
		#the ip address will be 192.168.1.1-23
		#first must check to ensure that the last block is smaller than the range value
		#to do this we must split the string to get the last block
		ipseries = iplist[0].split(".")
		if ipseries[3] > iplist[1]:
			print("[!] First host number must be smaller than the second value!")
			print("[!] Exiting program...")
			sys.exit(1)
		#recreate the ip address (minus the last block which we will change dynamically)
		actualip = str(ipseries[0]) + "." + str(ipseries[1])  + "." + str(ipseries[2]) + "."
		iprange = range(int(ipseries[3]), int(iplist[1])+1)
		for ip in iprange:
			print("[->] IP Address: " + str(actualip) + str(ip))
			initiatePortScan(str(actualip) + str(ip))
	else:
		initiatePortScan(args.ipaddress)
except:
	sys.exit(1)

end_time = datetime.now()
elapsed_time = end_time - start_time
print("\n[*] Scan Completed")
print("[*] Elapsed Time " + str(elapsed_time))

#http://stackoverflow.com/questions/7541056/pinging-an-ip-range-with-scapy
#http://www.secdev.org/projects/scapy/doc/usage.html
#https://null-byte.wonderhowto.com/how-to/build-stealth-port-scanner-with-scapy-and-python-0164779/
#http://stackoverflow.com/questions/7427101/dead-simple-argparse-example-wanted-1-argument-3-results
#http://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python
#http://jvns.ca/blog/2013/10/31/day-20-scapy-and-traceroute/
#http://resources.infosecinstitute.com/port-scanning-using-scapy/
#http://stackoverflow.com/questions/7427101/dead-simple-argparse-example-wanted-1-argument-3-results