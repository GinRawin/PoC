FROM scratch
ADD fs /

ENV LD_PRELOAD=libnvram-faker.so

EXPOSE 80/tcp
EXPOSE 80/udp
EXPOSE 1900/tcp
EXPOSE 1900/udp

ENTRYPOINT ["/greenhouse/busybox", "sh", "/run_clean.sh"]

CMD ["qemu-arm-static", "--", "/usr/sbin/httpd", "-S", "-E", "/usr/sbin/ca.pem", "/usr/sbin/httpsd.pem"]