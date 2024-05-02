FROM ubuntu:bionic
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -qq update
RUN apt-get -qq upgrade
RUN apt-get install -qq  software-properties-common
RUN add-apt-repository ppa:yubico/stable
RUN apt-get -qq update
RUN apt-get install -qq libudev-dev libssl-dev libfido2-dev
RUN apt-get install -qq build-essential autoconf automake libtool pkg-config
RUN apt-get install -qq libpam-dev pamtester
COPY . /pam-u2f
WORKDIR /pam-u2f
RUN autoreconf -i .
RUN ./configure --disable-man
RUN make clean all install
