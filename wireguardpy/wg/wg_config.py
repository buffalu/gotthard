SERVER_CONFIG = """
[Interface]
PrivateKey = {private_key}
Address = {my_vpn_ip}/24
PostUp = iptables -A FORWARD -i {wg_interface} -j ACCEPT; iptables -A FORWARD -o {wg_interface} -j ACCEPT; iptables -t nat -A POSTROUTING -o {external_ifc} -j MASQUERADE
PostDown = iptables -D FORWARD -i {wg_interface} -j ACCEPT; iptables -D FORWARD -o {wg_interface} -j ACCEPT; iptables -t nat -D POSTROUTING -o {external_ifc} -j MASQUERADE
ListenPort = {port}

[Peer]
PublicKey = {public_key}
AllowedIPs = {allowed_ips}/32
"""

CLIENT_CONFIG = """
[Interface]
PrivateKey = {my_private_key}
Address = {my_ip}
DNS = 1.1.1.1

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_ip}:{port}
AllowedIPs = 0.0.0.0/0
"""


class WireguardClientConfig(object):
    def __init__(self, my_ip: str, my_private_key: str, server_public_key: str, server_ip: str, port: int):
        self.my_ip = my_ip
        self.my_private_key = my_private_key
        self.server_public_key = server_public_key
        self.server_ip = server_ip
        self.port = port

    def generate_file_contents(self) -> str:
        return CLIENT_CONFIG.format(my_ip=self.my_ip, my_private_key=self.my_private_key,
                                    server_public_key=self.server_public_key, server_ip=self.server_ip, port=self.port)


class WireguardServerConfig(object):
    def __init__(self,
                 private_key: str,
                 my_vpn_ip: str,
                 wg_interface: str,
                 external_ifc: str,
                 port: int,
                 public_key: str,
                 allowed_ips: str):
        """

        Args:
            private_key:
            my_vpn_ip:
            wg_interface:
            external_ifc:
            port:
            public_key:
            allowed_ips: TODO: client should allow no IPs unless that's feature is enabled (sharing their internet).
        """
        self.private_key = private_key
        self.my_vpn_ip = my_vpn_ip
        self.wg_interface = wg_interface
        self.external_ifc = external_ifc
        self.port = port
        self.public_key = public_key
        self.allowed_ips = allowed_ips

    def generate_file_contents(self) -> str:
        """
        Returns:
            string with wireguard configuration file contents
        """
        return SERVER_CONFIG.format(private_key=self.private_key,
                                    my_vpn_ip=self.my_vpn_ip,
                                    wg_interface=self.wg_interface,
                                    external_ifc=self.external_ifc,
                                    port=self.port,
                                    public_key=self.public_key,
                                    allowed_ips=self.allowed_ips)


if __name__ == '__main__':
    config_contents = WireguardServerConfig("foo", "10.10.10.1", "wg0", "eth0", 123, "bar",
                                            "10.10.10.2").generate_file_contents()
    print(config_contents)
