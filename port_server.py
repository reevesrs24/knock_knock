from scapy.all import *
import os
import sys
import time

ips = {}

def start_port_knock_server(pkt):

	#if IP in pkt:
	#	print "DST = " + str(pkt[IP].dst) + " SRC = " + str(pkt[IP].src)
	
	if TCP in pkt and pkt[IP].src not in ips:
		ips[pkt[IP].src] = []
		ip_port_tup = ( time.time() , pkt[TCP].dport )
		ips[pkt[IP].src].append(ip_port_tup)

	elif TCP in pkt:
		ip_port_tup = ( time.time() , pkt[TCP].dport )
		ips[pkt[IP].src].append(ip_port_tup)

		print "IP = " + str(pkt[IP].src) + " Port = " + str(pkt[TCP].dport)
    

if __name__ == "__main__":
    sniff(iface="wlxf0795974b040", prn=start_port_knock_server, filter="", store=0)