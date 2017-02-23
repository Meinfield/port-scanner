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

# globalstart_time = datetime.now()
# globalend_time = datetime.now()

def checkHostLive(hostaddress):
	conf.verb = 0 #disable any output from scapy itself
	try:
		ping = sr1(IP(dst = hostaddress)/ICMP(), timeout=3) #craft icmp packet
		print("[*] Target is up, Beginning Scan")
	except Exception:
		print("\n[!] Unable to find host!")
		print("[!] Exiting program...")
		sys.exit(1)

def TCPscanThePort(hostaddress, portnumber):
	srcport = RandShort() #pick a random number for the source port
	conf.verb = 0 #disable any output from scapy itself
	SYNACKpkt = sr1(IP(dst = hostaddress)/TCP(sport=srcport,dport=portnumber,flags='S'),timeout=10)
	#set the destination, the source port, and destination port. Flag S means SYN packet
	if str(type(SYNACKpkt)) == "<type 'NoneType'>": #attempts to find filtered ports
		return 2
	elif SYNACKpkt.haslayer(TCP):
		if SYNACKpkt.getlayer(TCP).flags == 0x12:
			RSTpkt = sr(IP(dst = hostaddress)/TCP(sport=srcport,dport=portnumber,flags="R"),timeout=10)
			#send the reset packet to close the connection
			return 1
		elif SYNACKpkt.getlayer(TCP).flags == 0x14:
			return 0
	elif SYNACKpkt.haslayer(ICMP): #again attempts to find filtered ports
		if(int(SYNACKpkt.getlayer(ICMP).type) == 3 and int(SYNACKpkt.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return 2
	else:
		return 0

def UDPscanThePort(hostaddress, portnumber):
	udp_scan_resp = sr1(IP(dst=hostaddress)/UDP(dport=portnumber),timeout=10)
	
	if str(type(udp_scan_resp)) == "<type 'NoneType'>": #attempts to find filtered ports
		return 2
	if udp_scan_resp.haslayer(UDP):
		return 1
	elif udp_scan_resp.haslayer(ICMP): #again attempts to find filtered ports
		if(int(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP.code) == 3)):
			return 0
		if(int(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
			return 2
	else:
		return 0

def ICMPscan(hostaddress, portnumber):
	ping = sr1(IP(dst = hostaddress)/ICMP(dport=portnumber), timeout=3) #craft icmp packet
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
	ans,unans=sr(IP(dst=destinationaddress,ttl=(1,10))/TCP(dport=53,flags="S"))
	ans.summary( lambda(s,r) : r.sprintf("%IP.src%\t{ICMP:%ICMP.type%}\t{TCP:%TCP.flags%}"))

def initiatePortScan(ip):
	resultslist = [] #location to place everything into for writing to a file
	#range of ports
	try:
		portrange = args.port
		portlist = portrange.split("-") #split the string into two numbers
		if len(portlist) > 2: #if there are a bunch of ranges
			print("[!] Please correctly specify a range of ports!")
			print("[!] Exiting program...")
			sys.exit(1)
		elif len(portlist) > 1:
			if portlist[0] > portlist[1]: #make sure the numbers are all good
				print("[!] First port number must be smaller than the second value!")
				print("[!] Exiting program...")
				sys.exit(1)
			portrange = range(int(portlist[0]), int(portlist[1])+1) #create a range of numbers to go through
			try:
				checkHostLive(ip) #make sure host exists
				print("[*] Initiated scanning at " + strftime("%H:%M:%S") + "\n")
				for port in portrange:
					if str(args.protocol) == "UDP":
						status = UDPscanThePort(ip, int(port))
					else:
						status = TCPscanThePort(ip, int(port))
					if status == 1:
						resultslist.append("Port " + str(port) + ": Open")#for writing to a file
						print("Port " + str(port) + ": Open")
					elif status == 2:
						resultslist.append("Port " + str(port) + ": Filtered")#for writing to a file
						print("Port " + str(port) + ": Filtered")
					else:
						resultslist.append("Port " + str(port) + ": Closed")#for writing to a file
						print("Port " + str(port) + ": Closed")
				return resultslist
			except:
				print("\n[!] Unknown problem detected!")
				print("[!] Exiting program...")
				sys.exit(1)
		elif len(portlist) == 1: #if there is only one number
			checkHostLive(ip)
			print("[*] Initiated scanning at " + strftime("%H:%M:%S") + "\n")
			if str(args.protocol) == "UDP":

				status = UDPscanThePort(ip, int(args.port))
				print("why")
			else:
				status = TCPscanThePort(ip, int(args.port))
			
			if status == 1:
				resultslist.append("Port " + str(args.port) + ": Open")#for writing to a file
				print("Port " + str(args.port) + ": Open")
			elif status == 2:
				resultslist.append("Port " + str(args.port) + ": Filtered")#for writing to a file
				print("Port " + str(args.port) + ": Filtered")
			else:
				resultslist.append("Port " + str(args.port) + ": Closed")#for writing to a file
				print("Port " + str(args.port) + ": Closed")
			return resultslist
	except:
		#no port specified
		for port in range(1,101):
			if str(args.protocol) == "UDP":
				status = UDPscanThePort(ip, int(port))
			else:
				status = TCPscanThePort(ip, int(port))
			if status == 1:
				resultslist.append("Port " + str(port) + ": Open")#for writing to a file
				print("Port " + str(port) + ": Open")
			elif status == 2:
				resultslist.append("Port " + str(port) + ": Filtered")#for writing to a file
				print("Port " + str(port) + ": Filtered")
			else:
				resultslist.append("Port " + str(port) + ": Closed")#for writing to a file
				print("Port " + str(port) + ": Closed")
		return resultslist

def writeToFile(resultslist):
	print("[*] Writing to File " + str(args.write))
	filename = args.write + '.html'
	f = open(filename,'w')

	wrapper = """<html>
	<title>Port Scan Results</title>
		<body>
			<h2>Phillip's Fantastic Port Scanner</h2>
			<h4>Results:</h4>
			<ul>"""
	for i in resultslist:
			wrapper += '<li>%s</li>' % i #for each item in the list, write it out

	wrapper += """
			</ul>
		</body>
	</html>"""

	f.write(wrapper) #write to the file
	f.close() #close the file

#MAIN FUNCTIONS - this will populate the help portion
parser = argparse.ArgumentParser(description='This is a simple port scanner')
parser.add_argument('-i', '--ipaddress', action="store", help='Type in IP address of host machine; Type in multiple hosts by adding a "-<last host\'final two digits>"')
parser.add_argument('-p', '--port', action="store", help='Type in port(s) you wish to scan (use a dash to indicate the range), default is ports 1 -100')
parser.add_argument('-t', '--traceroute', action="store", help='Type in IP address you wish to get a route to')
parser.add_argument('-u', '--protocol', action="store", help='Type in UDP or TCP after, default is TCP')
parser.add_argument('-w', '--write', action="store", help='Type in the filename you would like to save the results as')
args = parser.parse_args() #gets the arguments

start_time = datetime.now()
SYNACK = 0x12
RSTACK = 0x14

signal.signal(signal.SIGINT, signal_handler) #if ctrl + C is pressed please stop

print("[*] Starting Phillip's Fantastic Port Scanner\n")

#check for if anything is possbile
if args.traceroute is None and args.ipaddress is None:
	print("[!] Please insert a correct argument, type '-h' or '--help' for assistance")
	sys.exit(1);

#check for traceroute
if args.traceroute is not None:
	traceroute(args.traceroute)

resultslist = [] #this will eventually contain all results

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
			resultslist.append(str(actualip) + str(ip))#get the ip address into the list
			listofports = initiatePortScan(str(actualip) + str(ip))#run the port scan and get back the results
			resultslist.append(listofports)#append the results after the ip address
	else:
		resultslist.append(str(args.ipaddress)) #get the ip address into the list
		listofports = initiatePortScan(args.ipaddress) #run the port scan and get back the results
		resultslist.append(listofports) #append the results after the ip address
except:
	sys.exit(1)

if args.write is not None: #if the write flag exists then run the code
	writeToFile(resultslist)

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
#http://stackoverflow.com/questions/1475123/easiest-way-to-turn-a-list-into-an-html-table-in-python