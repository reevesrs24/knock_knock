from scapy.all import *
import sys
import time
import socket
import SimpleHTTPServer
import SocketServer
import requests

serverIP= '172.16.96.65'
myIP='172.16.96.18'
########################################
def simple_tcp_server():

	PORT = 8001
	Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
	httpd = SocketServer.TCPServer((myIP, PORT), Handler)
	print "serving at port", PORT
	httpd.serve_forever()
	
#######################################

def sniffing(pket):
	#print('starting sniffing function...')
	if IP in pket and pket[IP].src == serverIP:
		print(pket.show())
		print ("Load: ", pket[Raw].load)
		

ports=[1000,2000,3000]

for port in ports:
	p = sr(IP(dst='172.16.96.65')/TCP(dport=port,flags="S"), timeout=.2)
	print ("port: ", port)
	print('\n-------------------\n')
	
	time.sleep(.5)

sniff(iface="wlan0", prn=sniffing, filter="", store=0, timeout=3)
print("ssh port received...")




exit(0)
