#!/usr/bin/env bash

if [ "$1" == "build" ]
then
	docker build -t sweyntooth:latest .
	if [ "$2" == "release" ]
	then
		mkdir -p release
		docker image save sweyntooth | gzip -9 -c > release/sweyntooth.tar.gz
		chmod a+rw release/sweyntooth.tar.gz
		echo "Image release/sweyntooth.tar.gz created!"
	fi

elif [ "$1" == "run" ]
then
	if [ -z $2 ] 
	then
		echo "Insert python script name to start"
		exit
	fi

	docker run --privileged --rm -e test="$2" -e port=$3 -e addr=$4 -ti --mount type=bind,source="$(pwd)"/logs,target=/logs sweyntooth # Start sweyntooth container

elif [ "$1" == "shell" ]
then
	docker run --rm --entrypoint bash --mount type=bind,source="$(pwd)"/logs,target=/logs -ti sweyntooth # Start container with bash and mount files

else
	echo "---------  HELP -------------"
	echo "sudo ./docker run <script_name> <serial_port> <ble_target_address> - Start any sweyntooth script by its name (<script_name>)"
	echo "sudo ./docker build                                                - Build docker container"
	echo "sudo ./docker build release                                        - Build docker container and create compressed image for release"
	echo "sudo ./docker shell                                                - Start docker container shell"
	echo "---------- EXAMPLE ----------"
	echo "./docker.sh run extras/Microchip_and_others_non_compliant_connection.py /dev/ttyACM0 f0:f8:f2:da:09:63"
fi