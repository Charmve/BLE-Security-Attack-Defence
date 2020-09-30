#!/bin/bash

if ! which nrfutil > /dev/null; 
then
  echo "nrfutil not found, installing now..."
  sudo pip install nrfutil 
else
  echo "nrfutil found!"
fi

echo $1
sudo nrfutil dfu usb-serial -p $1 -pkg nRF52_driver_firmware.zip
