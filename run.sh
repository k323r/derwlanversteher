#!/bin/bash

if [ ! -e $(which airmon-ng) ]
then
	echo "please install aircrack.. exiting"
fi

if [[ ! -z $1 && -e /sys/class/net/$1 ]]
then
	INTERFACE=$1
	echo "using interface $INTERFACE"
fi


