FROM ubuntu:20.04
RUN apt-get update && apt-get -y install vim curl
COPY fs /fs
CMD ["./fs/run_debug.sh"]
