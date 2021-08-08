
apt-get update && apt-get install -y python3.9 python3-pip python3-dev wireguard net-tools iproute2 iptables openresolv iputils-ping vim  \
&& apt-get install -y python3-pip python3-dev   && cd /usr/local/bin   && ln -s /usr/bin/python3 python  && pip3 install --upgrade pip

