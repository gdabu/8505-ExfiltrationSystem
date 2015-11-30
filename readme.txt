Here are some basic steps to walk through our backdoor server and client application. You do not need to specify any parameters in “server.py” but you should include some parameters in “client.py” program.

1.
	Run “server.py” 
	- python server.py

2. 
	Run “client.py” with parameters
	- python client.py -d (destination IP) -s (source IP) -p (destination port) -f (filepath of watching directory)
	
	eg.
	- python client.pu -d 192.168.0.13 -s 192.168.0.12 -p 80 -f /root/Documents



	For command execution, simply type out what you want to get. For example, if you want to some information about IP you type “ip addr” after command prompt “New Input: “ 

	eg.
	***New input: ip addr


	For file transferring, we need to specify it in the parameter at the beginning of the program (client.py)
	
