import subprocess
from typing import Dict, Tuple


class WireguardIfc(object):
    """
    An interface to the system-level wireguard.
    """

    @staticmethod
    def generate_server_client_keypair() -> Dict[str, Tuple[str, str]]:
        server_keypair = WireguardIfc.generate_keypair()
        client_keypair = WireguardIfc.generate_keypair()
        return {
            "server": server_keypair,
            "client": client_keypair
        }

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        private_key = WireguardIfc.generate_private_key()
        return (private_key, WireguardIfc.generate_public_key(private_key))

    @staticmethod
    def generate_private_key() -> str:
        key = WireguardIfc._run_wg_cmd("wg genkey").decode("utf-8").strip()
        return key

    @staticmethod
    def generate_public_key(private_key: str) -> str:
        pipe = subprocess.Popen(["echo", private_key], stdout=subprocess.PIPE)
        pubkey = WireguardIfc._run_wg_cmd("wg pubkey", pipe.stdout).decode("utf-8").strip()
        return pubkey

    @staticmethod
    def is_installed() -> bool:
        """
        Checks wireguard version to determine if it's installed or not.

        Returns: True if installed, False if not.
        """
        try:
            WireguardIfc._run_wg_cmd("wg -v")
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            return False

    @staticmethod
    def wg_quick_up(wg_ifc_name: str):
        return WireguardIfc._run_wg_cmd(f"wg-quick up {wg_ifc_name}")

    @staticmethod
    def wg_quick_down(wg_ifc_name: str):
        return WireguardIfc._run_wg_cmd(f"wg-quick down {wg_ifc_name}")

    @staticmethod
    def _run_wg_cmd(cmd_str: str, stdin=None) -> bytes:
        result = subprocess.check_output(cmd_str.split(" "), stderr=subprocess.STDOUT, stdin=stdin)
        return result


if __name__ == '__main__':
    print(f"Wireguard installed: {WireguardIfc.is_installed()}")

    private_key = WireguardIfc.generate_private_key()
    print(f"Wireguard private key: {private_key}")

    pub_key = WireguardIfc.generate_public_key(private_key)
    print(f"Wireguard public key: {pub_key}")

    print(WireguardIfc.generate_server_client_keypair())