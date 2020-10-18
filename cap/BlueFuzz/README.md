# BlueFuzz
BlueFuzz is a Bluetooth fuzz tester.
The scanner (bluetooth_scanner.py) is general purpose, while the pseudo-random data generator is customized for OBDII-Bluetooth car adapter.

NOTE: needs tshark installed and root privileges to create .pcap output file with bluetooth traffic

Prerequisites
=======

    sudo apt-get install bluetooth
    sudo apt-get install bluez
    sudo apt-get install python-bluez

    sudo apt-get install libbluetooth-dev bluez-hcidump  libboost-python-dev libboost-thread-dev libglib2.0-dev
    
    sudo apt-get install tshark

    pip install pybluez gattlib

    sudo adduser lp $(whoami)
    sudo reboot

Scanning for bluetooth devices with BlueFuzz 
==========================================

    sudo python bluetooth_scanner.py
