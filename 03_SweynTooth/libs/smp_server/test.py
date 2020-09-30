from scapy.all import *
from scapy.layers.bluetooth import SM_Master_Identification
from scapy.layers.bluetooth import SM_Identity_Information
from scapy.layers.bluetooth import SM_Pairing_Request
from scapy.layers.bluetooth import SM_Confirm
from scapy.layers.bluetooth import SM_Random
import BLESMPServer

master_address = '5d:36:ac:90:0b:22'
slave_address = '50:36:ac:90:0b:20'
ia = ''.join(map(lambda x: chr(int(x, 16)), master_address.split(':')))
ra = ''.join(map(lambda x: chr(int(x, 16)), slave_address.split(':')))

BLESMPServer.set_iocap(0x03)  # NoInputNoOutput

BLESMPServer.configure_connection(ia, ra, 0, 0x03, 0)

s = HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request()

data = bytearray(raw(s))

# hci_res = BLESMPServer.send_hci(data)
hci_res = BLESMPServer.pairing_request()
if hci_res is not None:
    pkt = HCI_Hdr(hci_res)
    print(pkt.summary())
    pkt.show()
    print('---------------------')
