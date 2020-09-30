import binascii
import os
import sys

import serial
import serial.tools.list_ports

sys.path.insert(0, os.getcwd() + '../libs')
from colorama import Fore
from scapy.utils import raw, wrpcap
from scapy.layers.bluetooth4LE import BTLE, NORDIC_BLE

# USB Serial commands
NRF52_CMD_DATA = b'\xA7'
NRF52_CMD_DATA_TX = b'\xBB'
NRF52_CMD_CHECKSUM_ERROR = b'\xA8'
NRF52_CMD_CONFIG_AUTO_EMPTY_PDU = b'\xA9'
NRF52_CMD_CONFIG_ACK = b'\xAA'
NRF52_CMD_CONFIG_LOG_TX = b'\xCC'
NRF52_CMD_CONFIG_NESNSN = b'\xAD'
NRF52_CMD_CONFIG_NESN = b'\xAE'
NRF52_CMD_CONFIG_SN = b'\xAF'
NRF52_CMD_BOOTLOADER_SEQ1 = b'\xA6'
NRF52_CMD_BOOTLOADER_SEQ2 = b'\xC7'
NRF52_CMD_LOG = b'\x7F'


# Driver class
class NRF52Dongle:
    n_debug = False
    n_log = False
    logs_pcap = False
    event_counter = 0
    packets_buffer = []
    pcap_filename = None
    pcap_tx_handover = False
    sent_pkt = None

    # Constructor ------------------------------------
    def __init__(self, port_name=None, baudrate=115200, debug=False, logs=True, logs_pcap=False, pcap_filename=None):

        if port_name is None:
            found = False
            ports = serial.tools.list_ports.comports()
            for port in ports:
                if 'Bluefruit nRF52840' in port.description:
                    port_name = port.device
                    found = True
            if not found:
                print(Fore.RED + 'nRF52840 was not found')

        self.serial = serial.Serial(port_name, baudrate, timeout=1)
        self.logs_pcap = logs_pcap
        self.n_log = logs
        self.n_debug = debug
        if pcap_filename == None:
            self.pcap_filename = os.path.basename(__file__).split('.')[0] + '.pcap'
        else:
            self.pcap_filename = pcap_filename

        self.set_log_tx(0)

        if self.n_debug:
            print('NRF52 Dongle: Instance started')

    def close(self):
        print('NRF52 Dongle closed')

    def save_pcap(self):
        wrpcap(self.pcap_filename, self.packets_buffer)  # save packet just sent
        # del self.packets_buffer
        self.packets_buffer = []

    # RAW functions ---------------------------
    def raw_send(self, pkt):
        raw_pkt = bytearray(pkt[:-3])  # Cut the 3 bytes CRC
        crc = bytearray([sum(raw_pkt) & 0xFF])  # Calculate CRC of raw packet data
        pkt_len = len(raw_pkt)  # Get raw packet data length
        l = bytearray([pkt_len & 0xFF, (pkt_len >> 8) & 0xFF])  # Pack length in 2 bytes (little infian)
        data = NRF52_CMD_DATA + l + raw_pkt + crc
        self.serial.write(data)

        if self.n_debug:
            print('Bytes sent: ' + binascii.hexlify(data).upper())

        return data

    def send(self, scapy_pkt, print_tx=True, force_pcap_save=False):
        self.raw_send(raw(scapy_pkt))
        if self.logs_pcap and (self.pcap_tx_handover is 0 or force_pcap_save):
            self.packets_buffer.append(NORDIC_BLE(board=75, protocol=2, flags=0x3) / scapy_pkt)
        if print_tx:
            print(Fore.CYAN + "TX ---> " + scapy_pkt.summary()[7:])

    def raw_receive(self):
        c = self.serial.read(1)
        # Receive BLE adv or channel packets
        if c == NRF52_CMD_DATA or c == NRF52_CMD_DATA_TX:
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            sz = lb | (hb << 8)
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            evt_counter = lb | (hb << 8)
            data = bytearray(self.serial.read(sz))
            checksum = ord(self.serial.read(1))
            if (sum(data) & 0xFF) == checksum:
                # If the data received is correct
                self.event_counter = evt_counter

                if c == NRF52_CMD_DATA_TX:
                    self.sent_pkt = data
                    n_flags = 0x03
                    ret_data = None
                else:  # Received packets
                    n_flags = 0x01
                    ret_data = data

                if self.logs_pcap is True and data != None:
                    self.packets_buffer.append(NORDIC_BLE(board=75, protocol=2, flags=n_flags) / BTLE(data))

                if self.n_debug:
                    print("Hex: " + binascii.hexlify(data).upper())

                return ret_data
        # Receive logs from dongle
        elif c == NRF52_CMD_LOG:
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            sz = lb | (hb << 8)
            data = self.serial.read(sz)
            if self.n_log:
                print(data)
        elif c == NRF52_CMD_CHECKSUM_ERROR:
            print(Fore.RED + "NRF52_CMD_CHECKSUM_ERROR")

        return None

    # Set the initial value of NESN and SN
    def set_nesnsn(self, value):
        # 0b01 -> set NESN, 0b10 -> set SN
        data = NRF52_CMD_CONFIG_NESNSN + bytearray([value])
        self.serial.write(data)

    # Set the initial value of NESN
    def set_nesn(self, value):
        data = NRF52_CMD_CONFIG_NESN + bytearray([value])
        self.serial.write(data)

    # Set the initial value of SN
    def set_sn(self, value):
        data = NRF52_CMD_CONFIG_SN + bytearray([value])
        self.serial.write(data)

    def get_tx_packet(self):
        pkt = self.sent_pkt
        self.sent_pkt = None
        return pkt

    # Makes the dongle send back the processed tx packet
    def set_log_tx(self, value):
        data = NRF52_CMD_CONFIG_LOG_TX + bytearray([value])
        self.serial.write(data)
        self.pcap_tx_handover = value
