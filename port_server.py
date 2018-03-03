from scapy.all import *
import os
import sys
import time

ips = {}
knock_seq = ['1000', '2000', '3000']

"""
	open the ssh server
"""
def open_ssh_server(ip):
	print 'Openening SSh.. '
	os.system('service ssh start')

"""
	Check the stores ip's port connection sequence
	Deternine whether it matches the predetermined knock sequence
"""

def check_knock_sequence(ip):
	#print 'Checking Knock Sequence...'
	knocks = ips[ip]['knocks']

	for i in range(0, 3):
		if knocks[i] != knock_seq[i]:
			return False
	return True
	#for tup in src_port_seq:


"""
	Check the the time that the src ip first made a connection attempt
	If the intitial time is greater than 10 seconds remove the element from the dictionary
	Else check the ip's stored port sequence to determine whether it matches the knock sequence 
"""

def check_time_seq(ip):
	'Checking ip time...'
	#print "Time " + str(ips[ip]['start_time'])
	if int(time.time()) - ips[ip]['start_time'] > 10:
		del ips[ip]
	elif check_knock_sequence(ip):
		open_ssh_server(ip)
    	



def start_port_knock_daemon(pkt):
	
	if TCP in pkt and pkt[IP].src not in ips and str(pkt[IP].dst) == '172.16.96.65':
		ip_obj = {'start_time' : int(time.time()), 'knocks' : []}
		ip_obj['knocks'].append(pkt[TCP].dport)
		ips[pkt[IP].src] = ip_obj
		print "SRC = " + str(pkt[IP].src) + " DST = " + str(pkt[IP].dst) + " Port = " + str(pkt[TCP].dport)

	elif TCP in pkt and str(pkt[IP].dst) == '172.16.96.65':
		ips[pkt[IP].src]['knocks'].append(pkt[TCP].dport)
		check_time_seq(pkt[IP].src)

		
    

if __name__ == "__main__":
    sniff(iface="wlxf0795974b040", prn=start_port_knock_daemon, filter="", store=0)