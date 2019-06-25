FROM ubuntu:18.04
MAINTAINER Aleksey Karpov <admin@bitaps.com>
RUN apt-get update
RUN apt-get -y install python3
RUN apt-get -y install python3-pip
RUN apt-get -y install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev
RUN apt-get -y install libssl1.0-dev
RUN apt-get -y install git
RUN apt-get -y install liblz4-dev
RUN apt install -y libgflags-dev libsnappy-dev zlib1g-dev libbz2-dev libzstd-dev g++ autoconf m4 automake pkg-config libtool
RUN git clone https://github.com/facebook/rocksdb.git
RUN cd rocksdb; make shared_lib; make install-shared INSTALL_PATH=/usr
RUN apt-get -y install libleveldb1v5 libleveldb-dev
COPY requirements.txt .
RUN pip3 install --requirement requirements.txt
RUN mkdir /config
RUN mkdir /app
COPY ./ ./app
WORKDIR /app
ENTRYPOINT ["python3", "main.py"]
