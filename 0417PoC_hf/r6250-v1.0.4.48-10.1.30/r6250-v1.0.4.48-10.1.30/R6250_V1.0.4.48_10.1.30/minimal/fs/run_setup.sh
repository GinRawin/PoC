#!/bin/sh

/greenhouse/busybox sh /setup_dev.sh /greenhouse/busybox /ghdev
/greenhouse/busybox cp -r /ghtmp/* /tmp
/greenhouse/busybox cp -r /ghetc/* /etc

/greenhouse/ip link add dummy0 type dummy
/greenhouse/ip addr add 192.168.1.1/24 dev dummy0
/greenhouse/ip link set dummy0 up
/greenhouse/ip link add dummy1 type dummy
/greenhouse/ip addr add 192.168.2.1/24 dev dummy1
/greenhouse/ip link set dummy1 up
/greenhouse/ip link add dummy2 type dummy
/greenhouse/ip addr add 192.168.1.2/24 dev dummy2
/greenhouse/ip link set dummy2 up
