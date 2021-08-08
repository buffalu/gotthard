from wg_ifc import WireguardIfc
from wg_config import WireguardServerConfig
import solana


def main():
    keypairs = WireguardIfc.generate_server_client_keypair()


if __name__ == '__main__':
    main()
