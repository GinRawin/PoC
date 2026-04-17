#!/bin/sh
mkdir /fs/tb_log

chroot /fs /run_setup.sh

chroot fs /qemu-arm-static -d trace:exec_tb -strace -D /tb_log/%d_tb_log.txt -E LD_PRELOAD=libnvram-faker.so  -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -d trace:exec_tb -strace -D /tb_log/%d_tb_log.txt -E LD_PRELOAD=libnvram-faker.so  -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /bin/sh /run_background.sh > /fs/GREENHOUSE_BGLOG 2>&1


chroot fs /qemu-arm-static -d trace:exec_tb -strace -D /tb_log/%d_tb_log.txt -E LD_PRELOAD=libnvram-faker.so  -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -d trace:exec_tb -strace -D /tb_log/%d_tb_log.txt -E LD_PRELOAD=libnvram-faker.so  -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem


while true; do sleep 10000; done