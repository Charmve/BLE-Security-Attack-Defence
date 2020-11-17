# BLE OpenSource Stack

* [Mynewt-Nimble](#mynewt-nimble)
  * [Overview](#overview)
  * [Supported hardware](#supported-hardware)
  * [Browsing](#browsing)
  * [Sample Applications](#sample-applications)
* [nRF5_SDK_15.0.0_a53641a](#nrf5_sdk_1500_a53641a)
* [PyBluez](#pybluez)
  * [Platform Support](#platform-support)
  * [Python Version Support](#python-version-support)
  * [Examples](#examples)
* [LightBlue](#lightblue)
  * [Requirements](#requirements)
  * [Installation](#installation)


    
# Mynewt-Nimble
<img src="http://mynewt.apache.org/img/logo.svg" width="250" alt="Apache Mynewt">

## Overview

Apache NimBLE is an open-source Bluetooth 5.1 stack (both Host & Controller)
that completely replaces the proprietary SoftDevice on Nordic chipsets. It is
part of [Apache Mynewt project](https://github.com/apache/mynewt-core).

Features highlight:
  - Support for 251 byte packet size
  - Support for all 4 roles concurrently - Broadcaster, Observer, Peripheral and Central
  - Support for up to 32 simultaneous connections.
  - Legacy and SC (secure connections) SMP support (pairing and bonding).
  - Advertising Extensions.
  - Coded (aka Long Range) and 2M PHYs.
  - Bluetooth Mesh.

## Supported hardware

Controller supports Nordic nRF51 and nRF52 chipsets. Host runs on any board
and architecture [supported](https://github.com/apache/mynewt-core#overview)
by Apache Mynewt OS.


## Browsing

If you are browsing around the source tree, and want to see some of the
major functional chunks, here are a few pointers:

- nimble/controller: Contains code for controller including Link Layer and HCI implementation
([controller](https://github.com/apache/mynewt-nimble/tree/master/nimble/controller))

- nimble/drivers: Contains drivers for supported radio transceivers (Nordic nRF51 and nRF52)
([drivers](https://github.com/apache/mynewt-nimble/tree/master/nimble/drivers))

- nimble/host: Contains code for host subsystem. This includes protocols like
L2CAP and ATT, support for HCI commands and events, Generic Access Profile (GAP),
Generic Attribute Profile (GATT) and Security Manager (SM).
([host](https://github.com/apache/mynewt-nimble/tree/master/nimble/host))

- nimble/host/mesh: Contains code for Bluetooth Mesh subsystem.
([mesh](https://github.com/apache/mynewt-nimble/tree/master/nimble/host/mesh))

- nimble/transport: Contains code for supported transport protocols between host
and controller. This includes UART, emSPI and RAM (used in combined build when
host and controller run on same CPU)
([transport](https://github.com/apache/mynewt-nimble/tree/master/nimble/transport))

- porting: Contains implementation of NimBLE Porting Layer (NPL) for supported
operating systems
([porting](https://github.com/apache/mynewt-nimble/tree/master/porting))

- ext: Contains external libraries used by NimBLE. Those are used if not
provided by OS
([ext](https://github.com/apache/mynewt-nimble/tree/master/ext))

- kernel: Contains the core of the RTOS ([kernel/os](https://github.com/apache/mynewt-core/tree/master/kernel/os))

## Sample Applications

There are also some sample applications that show how to Apache Mynewt NimBLE
stack. These sample applications are located in the `apps/` directory of
Apache Mynewt [repo](https://github.com/apache/mynewt-core). Some examples:

* [blecent](https://github.com/apache/mynewt-nimble/tree/master/apps/blecent):
A basic central device with no user interface.  This application scans for
a peripheral that supports the alert notification service (ANS). Upon
discovering such a peripheral, blecent connects and performs a characteristic
read, characteristic write, and notification subscription.
* [blehci](https://github.com/apache/mynewt-nimble/tree/master/apps/blehci):
Implements a BLE controller-only application.  A separate host-only
implementation, such as Linux's BlueZ, can interface with this application via
HCI over UART.
* [bleprph](https://github.com/apache/mynewt-nimble/tree/master/apps/bleprph): An
  implementation of a minimal BLE peripheral.
* [btshell](https://github.com/apache/mynewt-nimble/tree/master/apps/btshell): A
  shell-like application allowing to configure and use most of NimBLE
  functionality from command line.
* [bleuart](https://github.com/apache/mynewt-core/tree/master/apps/bleuart):
Implements a simple BLE peripheral that supports the Nordic
UART / Serial Port Emulation service
(https://developer.nordicsemi.com/nRF5_SDK/nRF51_SDK_v8.x.x/doc/8.0.0/s110/html/a00072.html).

<br>

# nRF5_SDK_15.0.0_a53641a

Nordic nrf52832

repo: https://github.com/lingyq/nRF5_SDK_15.0.0_a53641a

<br>

# PyBluez

[![Build Status](https://github.com/pybluez/pybluez/workflows/Build/badge.svg)](https://github.com/pybluez/pybluez/actions?query=workflow%3ABuild)

repo: https://github.com/Charmve/pybluez

The PyBluez module allows Python code to access the host machine's Bluetooth
resources.


## Platform Support

| Linux  | Raspberry Pi | macOS | Windows |
|:------:|:------------:|:-----:|:-------:|
| :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |


## Python Version Support

| Python 2 | Python 3 (min 3.5) |
|:--------:|:------------------:|
| Till Version 0.22 | Version 0.23 and newer |



## Examples

```python
# simple inquiry example
import bluetooth

nearby_devices = bluetooth.discover_devices(lookup_names=True)
print("Found {} devices.".format(len(nearby_devices)))

for addr, name in nearby_devices:
    print("  {} - {}".format(addr, name))
```

```python
# bluetooth low energy scan
from bluetooth.ble import DiscoveryService

service = DiscoveryService()
devices = service.discover(2)

for address, name in devices.items():
    print("name: {}, address: {}".format(name, address))
```

<br>

# LightBlue

LightBlue is a cross-platform Bluetooth API for Python which provides simple access to Bluetooth operations. It is available for Mac OS X, GNU/Linux and Nokia's Python for Series 60 platform for mobile phones.

repo: https://github.com/Charmve/lightblue-0.4

LightBlue provides simple access to:

    * Device and service discovery (with and without end-user GUIs)
    * Standard socket interface for RFCOMM and L2CAP sockets (currently L2CAP client sockets only, and not on PyS60)
    * Sending and receiving files over OBEX
    * Advertising of RFCOMM and OBEX services
    * Local device information

LightBlue is released under the GPL License.

See the home page at http://lightblue.sourceforge.net for more information.


## Requirements

Mac OS X:
    Python 2.3 or later
    PyObjC (http://pyobjc.sourceforge.net)
    Xcode 2.1 or later to build LightAquaBlue framework (but you could build from a separate .xcode project for older versions)
    (Mac OS X 10.4 or later is required to do device discovery without a GUI)
    
GNU/Linux:
    Python 2.3 or later (with Tkinter if using selectdevice() or selectservice())
    PyBluez 0.9 or later (http://org.csail.mit.edu/pybluez)
    OpenOBEX 1.0.1 or later (http://openobex.sourceforge.net)
    
Python for Series 60:
    Python for Series 60 1.3.1 or later (http://sourceforge.net/projects/pys60)
    
    
## Installation

Mac OS X and GNU/Linux:
    Just open up a shell/terminal and run the command:

        python setup.py install

Or you might need to run with root access, i.e.

	sudo python setup.py install

    On Mac OS X, the setup.py script also installs the LightAquaBlue framework into /Library/Frameworks.
    
Python for Series 60: 
    Download the appropriate SIS file for your phone from the LightBlue home page (http://lightblue.sourceforge.net). Send the file to your phone, and open and install. Or, use the Nokia PC Suite to install the SIS file.
    
<br>
* <i>Update by Sep 30，2020 @<a href="https://github.com/Charmve" target="_blank">Charmve</a>, follow me</i>
