FROM python:3.9.18-bullseye

RUN echo "installing dependencies" \
	&& apt-get update && apt-get install -y build-essential libpcap-dev vim curl wget subversion zip

WORKDIR /opt/

RUN git clone https://github.com/jchavanton/pcapsipdump.git
RUN cd pcapsipdump && make && make install

COPY entry.sh /
ENTRYPOINT ["/entry.sh"]
