FROM ubuntu:18.04

RUN apt-get update && \
    apt-get install software-properties-common -y && \
    add-apt-repository ppa:ethereum/ethereum -y && \
    apt-get update && \
    apt-get install -y \
    wget unzip curl \
    build-essential cmake git libgmp3-dev libprocps-dev python-markdown libboost-all-dev libssl-dev pkg-config python3-pip solc

WORKDIR /root/roll_up

COPY . .

RUN pip3 install -r requirements.txt

RUN cd build \
    && cmake .. \
    && make \
    && DESTDIR=/usr/local make install \
        NO_PROCPS=1 \
        NO_GTEST=1 \
        NO_DOCS=1 \
        CURVE=ALT_BN128 \
        FEATUREFLAGS="-DBINARY_OUTPUT=1 -DMONTGOMERY_OUTPUT=1 -DNO_PT_COMPRESSION=1"

ENV LD_LIBRARY_PATH $LD_LIBRARY_PATH:/usr/local/lib
