#!/bin/sh

ifconfig eth0 192.168.100.1 netmask 255.255.255.0 up >/dev/null 2>&1
/sbin/route add default gw 192.168.1.1
