##################################################################################
##  SOURCE FILE:    AesEncryption.py
##
##  AUTHOR:         Geoff Dabu
##
##  PROGRAM:
##
##
##  FUNCTIONS:      stopfilter(packet)
##					main()
##
##  DATE:           October 17, 2015
##
##################################################################################
import sys, os, argparse, socket, logging
from scapy.all import *
from AesEncryption import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
message = []

##################################################################################
##  FUNCTION
##
##  Name:       	stopfilter
##  Parameters:		packet - a packet that is passed in through sniffed
##  Return Values:	boolean - true, if sniff function ends. false, if sniff
##					function continues.
##  Description:	Determines whether the client continues to sniff for packets.
##					The client only continues if there is a pkt with payload.
##################################################################################
def stopfilter(pkt):
	global message

	if ARP in pkt:
		return False
	if UDP in pkt and pkt['UDP'].sport != 128:
		message.append(pkt['UDP'].sport)
	if UDP in pkt and pkt['UDP'].sport == 128:
		print decrypt(pkt['Raw'].load)
		print message
		return True

##################################################################################
##  FUNCTION
##
##  Name:       	main
##  Parameters:		n/a
##  Return Values:	n/a
##  Description:	Prompts the user for a command, encrypts it and sends it to
##					the server.
##################################################################################
def main():
	secret = ""
	global message

	cmdParser = argparse.ArgumentParser(description="8505A3-PortKnock Client")
	cmdParser.add_argument('-d','--dstIp',dest='dstIp', help='Destination address of the host to send the message to.', required=True)
	cmdParser.add_argument('-s','--srcIp',dest='srcIp', help='Source address of the host thats sending.', required=True)
	cmdParser.add_argument('-p','--dstPort',dest='dstPort', help='Destination port of the host to send the message to.', required=True)
	args = cmdParser.parse_args();

	pkt = IP(dst=22, src=args.srcIp)/UDP(dport=int(args.dstPort), sport=8000)/"/root/Documents/"
	send(pkt)

	while 1:
		payload = raw_input("Some input please: ")
		pkt = IP(dst=args.dstIp, src=args.srcIp)/UDP(dport=int(args.dstPort), sport=8000)/encrypt(payload)
		send(pkt)
		sniff(filter="udp and (dst port 8000 and src " + args.dstIp + ")", stop_filter=stopfilter)

		for m in message:
			secret += chr(m)

		print decrypt(secret)

		secret = ""
		message = []

if __name__ == '__main__':
	main()
