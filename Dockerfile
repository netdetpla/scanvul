FROM debian:latest 

ADD ["sources.list", "/etc/apt/"]

RUN apt update \
    && apt -y install python3 gcc git make libpcap-dev wget alien default-libmysqlclient-dev python3-dev \
    && wget https://bootstrap.pypa.io/get-pip.py \
    && python3 get-pip.py \
    && wget https://nmap.org/dist/nmap-7.70-1.x86_64.rpm \
    && alien nmap*.rpm \
    && dpkg --install nmap*.deb \
    && pip install requests mysqlclient \
    && apt clean

ADD ["scanvul", "/"]

CMD python3 main.py


