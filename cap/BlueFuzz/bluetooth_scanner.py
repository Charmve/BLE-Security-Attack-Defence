import bluetooth
import subprocess
import time
import os
from obd_generator import *

SCANNER_TIME = 3

# NOTE: should be run as root

def main():
	
	try:
		# switch off subprocesses output
		devs = open(os.devnull,"w")
		
		# make directory with root privileges to store pcap output file
		# tshark output can be stored only in root's directories
		subprocess.call("mkdir ./capture",shell=True,stdout=devs,stderr=devs)
		
		#run tshark with root privileges on bluetooth interface
		thread=subprocess.Popen(["tshark", "-w", "./capture/capture.pcap", "-i", "bluetooth0"],stdout=devs,stderr=devs)
		
		#STEP 1: BLUETOOTH SCANNER
		devices = bluetooth.discover_devices(lookup_names = True, flush_cache = True, duration = SCANNER_TIME)

		if len(devices) == 0:
			print ("No devices found")
			thread.terminate()
			quit()

		i=0
		dev_names = []
		dev_addr = []
		dev_services = []
		
		# print services for each discovered device
		for addr, name in devices:
			#device_name = bluetooth.lookup_name(addr)
			dev_addr.append(addr)
			dev_names.append(name)
			print "Device N." + str(i) + ": " + addr + ": " + name
			services = []	
			
			j=0
			for service in bluetooth.find_service(address = addr):
				print "   Service N: ", j
				print "   Name: ", service["name"]
				print "   Description: ", service["description"]
				print "   Protocol: ", service["protocol"]
				print "   Provider: ", service["provider"]
				print "   Port: ", service["port"]
				print "   Service id: ", service["service-id"]
				print ""
				services.append(service)
				j=j+1
			dev_services.append(services)
			i=i+1	
		
		
		#STEP 2: DEVICE CHOOSING
		try:
			userInput=(raw_input('Chose a device number for pairing (q for quit):'))
			if userInput == 'q':
				thread.terminate()
				quit()
			deviceNum = int(userInput)
		except ValueError:
			print "Not a number"
			thread.terminate()
			quit()
		if deviceNum >= len(devices):
			print "Input error: no such device"
			thread.terminate()
			quit()

		address = dev_addr[deviceNum]
		name = dev_names[deviceNum]
		print "You have chosen device " + str(deviceNum) + ": " + address + "(" + name + ")"
		
		#STEP 3: CHOSE SERVICE
		try:
			serviceNum = int(raw_input('Chose the service number :'))         # RFCOMM port
		except ValueError:
			print "Not a number"
			thread.terminate()
			quit()
		chosen_services = dev_services[deviceNum]
		if serviceNum >= len(chosen_services):
			print "Input error: no such service"
			thread.terminate()
			quit()
		chosen_service = chosen_services[serviceNum]
		protocol = chosen_service["protocol"]
		port = chosen_service["port"]
		
		print "protocol: " + protocol
		print "port: ", port
			
		#STEP 4: PAIRING
		try:
			# bluetooth protocol for OBD-II interaction: RFCOMM
			if protocol == "RFCOMM":
				socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
			elif protocol == "L2CAP":
				socket = bluetooth.BluetoothSocket(bluetooth.L2CAP)
			else:
				print "Protocol not supported"
				thread.terminate()
				quit()
			
			socket.connect((address,port))
			print "Device connected"
			
			# the first packet is equal to the first sent by the official application
			socket.send("ATZ\r")
			print "Sent: ATZ\r"
			time.sleep(1)
			# expected answer is "\r\rELM327 v1.5\r\r"
			
			# the second packet is equal to the second sent by the official application
			socket.send("ATD\r")
			print "Sent: ATD\r"
			time.sleep(1)
			# expected answer is "\rOK\r\r"
			
			while True:
				# send pseudo-random generated data
				data = generator()
				socket.send(data)
				print "Sent: ", data
				time.sleep(1)
				
			'''
				#To receive data
				received = socket.recv(1024) # Buffer size
				print "received: ", received
			'''
		
		except bluetooth.btcommon.BluetoothError as err:
			print err
			socket.close()
			thread.terminate()
			quit()
			
	except KeyboardInterrupt:
		# to intercept CRTL+C interrupt 		
		print "\nQuitting..."
		thread.terminate()
		quit()
		

if __name__ == "__main__":
	main()
