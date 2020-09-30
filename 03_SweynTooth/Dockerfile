FROM python:2.7.17-slim-buster
# Default script to execute
ENV test dhcheck_skip.py
ENV port /dev/ttyACM0
ENV addr ""
WORKDIR /
# Add main python scripts and folders
ADD *.py /
ADD drivers /drivers/
ADD libs /libs/ 
ADD extras /extras/
ADD captures /captures/
# Add helper files
ADD nRF52_driver_firmware.zip requirements.txt install_sweyntooth.sh flash_nRF52_driver_firmware.sh /

RUN mkdir -p /logs && apt update && chmod +x install_sweyntooth.sh && ./install_sweyntooth.sh && apt-get autoremove && apt-get clean
CMD [ "sh", "-c", "python ${test} ${port} ${addr} && find ./ -maxdepth 1 -name '*.pcap' -exec cp {} logs \\; && find ./extras -maxdepth 1 -name '*.pcap' -exec cp '{}' logs  \\;" ]