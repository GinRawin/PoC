#!/bin/sh

chroot /fs /run_setup.sh

chroot fs /qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /bin/sh /run_background.sh > /fs/GREENHOUSE_BGLOG 2>&1


chroot fs /qemu-arm-static -pconly -hackbind -hackproc -hacksysinfo -D /trace.log0 -strace -execve "/qemu-arm-static -pconly -hackbind -hackproc -hacksysinfo -strace -D /trace.log" -E LD_PRELOAD="libnvram-faker.so" /bin/sh qemu_run.sh > /fs/GREENHOUSE_STDLOG 2>&1
echo "Greenhouse_EXIT_CODE::"$? >> /fs/GREENHOUSE_STDLOG
echo "Greenhouse_EXIT_CODE::" > GH_DONE
while true; do sleep 10000; done
