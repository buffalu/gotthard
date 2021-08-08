import base64
import os
import time
import traceback
import uuid
from dataclasses import dataclass
from ipaddress import IPv4Address
import glob

import pydantic
from typing import Dict, Tuple, Optional, List

from anchorpy.program.namespace.account import AccountDoesNotExistError
from app.vpn_registry import VpnRegistry, CreateProviderAccountResponse, RegisterServerResponse, ProviderAccount
from networking.network import get_location, get_public_ip, get_default_route_interface

from solana.publickey import PublicKey as SolanaPublicKey
from nacl.public import PrivateKey, PublicKey, Box

from wg.wg_config import WireguardServerConfig, WireguardClientConfig
from wg.wg_ifc import WireguardIfc


class PostConnectionResponse(pydantic.BaseModel):
    success: bool
    msg: str = ""


class DeleteConnectionResponse(pydantic.BaseModel):
    success: bool
    msg: str = ""


@dataclass
class ConnectionContext:
    mode: str
    pk: PrivateKey
    wg_keypair: Tuple[str, str]
    other_end_solana_pubk: SolanaPublicKey  # address of entity on the other end

    # Fixed after connection details are worked out
    is_connected: bool = False

    uid: int = 0

    init_time: float = 0.0

    my_vpn_ip: Optional[IPv4Address] = None
    other_end_vpn_ip: Optional[IPv4Address] = None
    other_end_box_pubk: Optional[PublicKey] = None
    other_end_wg_pubk: str = ""
    wg_ifc: str = ""  # name of the wireguard interface
    port: int = 51820

    # Only relevant for providers
    server_public_ip: Optional[IPv4Address] = None
    default_interface: str = ""


class ConnectionStatusResponse(pydantic.BaseModel):
    connected: bool
    connected_to: str = ""


class ProviderStatusResponse(pydantic.BaseModel):
    is_provider: bool


class ConnectionManager(object):
    WG_FILE_LOCATION = "/tmp/wgconf/"

    LOCATION_SCALAR = 100

    def __init__(self, vpn_registry: VpnRegistry):
        self._vpn_registry = vpn_registry

        self._connections: Dict[str, ConnectionContext] = dict()

        self._server_uid = uuid.uuid1().int & 0xFFFFFFFF

        self._conn_count = 0

        self._provider_addr = self._vpn_registry.provider_associated_addr()
        self._is_provider = self.is_provider()

        # Create folder holding configurations, bring down any interfaces that are currently up, and clear out the folder
        if not os.path.exists(self.WG_FILE_LOCATION):
            os.mkdir(self.WG_FILE_LOCATION)

        for wgconf_fpath in glob.glob(os.path.join(self.WG_FILE_LOCATION, "*.conf")):
            try:
                WireguardIfc.wg_quick_down(wgconf_fpath)
            except:
                pass
            os.remove(wgconf_fpath)

    def connection_status(self) -> ConnectionStatusResponse:
        if self._connections:
            for conn in list(self._connections.values()):
                if conn.is_connected and conn.mode == "user":
                    return ConnectionStatusResponse(connected=True, connected_to=str(conn.other_end_solana_pubk))
        return ConnectionStatusResponse(connected=False)

    def all_providers(self) -> List[ProviderAccount]:
        """Returns all providers registered"""
        providers = self._vpn_registry.all_providers()
        for p in providers:
            for s in p.info.servers:
                s.lat /= self.LOCATION_SCALAR
                s.long /= self.LOCATION_SCALAR
        return providers

    def user_disconnect(self):
        user_conns = list(filter(lambda conn: conn.mode == "user", self._connections.values()))
        if user_conns:
            user_conn = user_conns[0]  # type: ConnectionContext
            server_owner = user_conn.other_end_solana_pubk
            owner_account_addr = self._vpn_registry._program.account.provider.associated_address(
                SolanaPublicKey(server_owner))
            acc = self._vpn_registry.get_provider(owner_account_addr)
            for c in acc.info.connections:
                if c.uid == user_conn.uid:
                    print(f"found server to disconnect from, sending disconnect", flush=True)
                    ret = self._vpn_registry.disconnect(owner_account_addr, server_owner)

                    wf_fpath = self._format_wg_conf_file(user_conn.wg_ifc)
                    print(f"Bringing down interface at file: {wf_fpath}", flush=True)
                    response = WireguardIfc.wg_quick_down(wf_fpath)
                    print(f"response from wg-quick down user disconnect={response}", flush=True)
                    os.remove(wf_fpath)
                    print(f"Brought down interface and deleted file", flush=True)

                    print(f"Testing location + ip...", flush=True)
                    new_location = get_location()
                    print(f"New location: {new_location=}", flush=True)

            # TODO: assume for now the user only has one connection
            self._connections.popitem()

    def post_provider(self) -> CreateProviderAccountResponse:
        """Posts provider account"""
        if not self._is_provider:
            ret = self._vpn_registry.create_provider()
            self._is_provider = True  # TODO: check return status on this to make sure the account was created
            return ret
        else:
            return CreateProviderAccountResponse(success=True,
                                                 account=str(self._provider_addr),
                                                 tx_id="",
                                                 msg="Provider account already exists")

    def is_provider(self) -> bool:
        """
        Checks to see if this account is a provider or not
        """
        try:
            self._vpn_registry.get_provider(self._provider_addr)
            return True
        except AccountDoesNotExistError:
            return False

    def post_server_info(self) -> RegisterServerResponse:
        """Provider posts information on this server."""
        # TODO: might want to consider raising for these errors/returning error codes?
        if not self._is_provider:
            return RegisterServerResponse(success=False, uid=0, latitude=0.0, longitude=0.0, tx_id="",
                                          msg="Not provideer")
        elif self.is_duplicate_server():
            return RegisterServerResponse(success=False, uid=0, latitude=0.0, longitude=0.0, tx_id="",
                                          msg="Duplicate server")
        else:
            # NOTE: this will be incorrect if connected to another VPN, but we'll assume that servers
            # won't be acting as users for now
            location_data = get_location()
            lat = int(location_data["latitude"] * self.LOCATION_SCALAR)
            long = int(location_data["longitude"] * self.LOCATION_SCALAR)
            success = self._vpn_registry.register_server(self._server_uid, lat, long)
            return RegisterServerResponse(success=success,
                                          uid=self._server_uid,
                                          latitude=lat / self.LOCATION_SCALAR,
                                          longitude=long / self.LOCATION_SCALAR,
                                          tx_id="")

    def is_duplicate_server(self) -> bool:
        """Returns True if duplicate server, False otherwise."""
        provider_acc = self._vpn_registry.get_provider(self._provider_addr)
        for s in provider_acc.info.servers:
            if s.uid == self._server_uid:
                return True
        return False

    def post_connection_request(self, program_id: str, uid: int) -> PostConnectionResponse:
        """
        User posts a connection request to a provider at address program_id with a given server uid.
        TODO: hackathon hacky, but if we get a connection request and are already connected, disconnect then send connection request
        """
        connection_status = self.connection_status()
        if connection_status.connected:
            self.user_disconnect()
            time.sleep(1.0)
        try:
            provider_acc = self._vpn_registry.get_provider(SolanaPublicKey(program_id))
            for s in provider_acc.info.servers:
                if s.uid == uid:
                    print(f"Found UID", flush=True)
                    conn_context = ConnectionContext(mode="user",
                                                     pk=PrivateKey.generate(),
                                                     wg_keypair=WireguardIfc.generate_keypair(),
                                                     other_end_solana_pubk=provider_acc.info.authority,
                                                     is_connected=False,
                                                     uid=uid,
                                                     init_time=time.time())
                    self._connections[str(provider_acc.info.authority)] = conn_context
                    wg_pubkey = base64.b64decode(conn_context.wg_keypair[1])
                    box_pub_key = bytes(conn_context.pk.public_key)
                    payload = wg_pubkey + box_pub_key
                    send_success = self._vpn_registry.connect(uid,
                                                              payload,
                                                              program_id,
                                                              provider_acc.info.authority)
                    print(f"Sent connection request", flush=True)
                    return PostConnectionResponse(success=send_success, msg="Connection request sent")
            print(f"UID doesnt exist", flush=True)
        except AccountDoesNotExistError:
            print(f"Account doesn't exist", flush=True)
            return PostConnectionResponse(success=False, msg="Provided program ID does not exist")

    def manage_connections(self):
        """
        Meant to be called periodically to manager connections
        TODO: event-based websocket would be more ideal.
        """
        try:
            if self._is_provider:
                acc = self._vpn_registry.get_provider(self._provider_addr)
                if acc.info.requests:
                    self._handle_connection_request(acc)
                self._check_connections(acc)
            else:
                user_conns = list(filter(lambda conn: conn.mode == "user", self._connections.values()))
                if user_conns:
                    user_conn = user_conns[0]
                    if not user_conn.is_connected:
                        self._handle_user_connection(user_conn)
        except:
            print(traceback.format_exc(), flush=True)

    def _check_connections(self, acc: ProviderAccount):
        conns_to_delete = list()
        connection_addrs = [c.user for c in acc.info.connections if time.time()]
        for addr in self._connections.keys():
            # Pretty hacky fix to make sure accounts aren't deleted to quick
            if addr not in connection_addrs and time.time() - self._connections[addr].init_time > 10:
                print(f"Need to delete {addr}", flush=True)
                conns_to_delete.append(addr)

        if conns_to_delete:
            for a in conns_to_delete:
                wg_file = self._format_wg_conf_file(self._connections[a].wg_ifc)
                response = WireguardIfc.wg_quick_down(wg_file)
                print(f"response from wg-quick down check connections={response}", flush=True)
                os.remove(wg_file)
                del self._connections[a]

            print(f"deleted connections: {conns_to_delete}", flush=True)

    def _handle_user_connection(self, user_conn: ConnectionContext):
        other_end_associated_addr = self._vpn_registry._program.account.provider.associated_address(
            SolanaPublicKey(user_conn.other_end_solana_pubk))
        acc = self._vpn_registry.get_provider(other_end_associated_addr)
        for c in acc.info.connections:
            if c.uid == user_conn.uid:  # TODO: make sure this isn't done multiple times after accepted
                print(f"Found our request in current connections, c={c}", flush=True)

                payload = bytes(c.conn_data)
                user_conn.other_end_box_pubk = PublicKey(payload[:32])

                # Decrypt payload to wg configuration settings
                box = Box(user_conn.pk, user_conn.other_end_box_pubk)
                decrypted = box.decrypt(payload[32:112])

                user_conn.other_end_wg_pubk = base64.b64encode(decrypted[:32]).decode()
                user_conn.server_public_ip = str(IPv4Address(int.from_bytes(decrypted[32:36], "little")))
                user_conn.my_vpn_ip = str(IPv4Address(int.from_bytes(decrypted[36:40], "little")))
                user_conn.wg_ifc = f"wg{self._conn_count}"

                wg_fcontents = WireguardClientConfig(
                    my_ip=user_conn.my_vpn_ip,
                    my_private_key=user_conn.wg_keypair[0],
                    server_public_key=user_conn.other_end_wg_pubk,
                    server_ip=user_conn.server_public_ip,
                    port=user_conn.port
                ).generate_file_contents()

                fpath = self._format_wg_conf_file(user_conn.wg_ifc)
                with open(fpath, "w") as f:
                    f.write(wg_fcontents)
                response = WireguardIfc.wg_quick_up(fpath)
                print(f"response from wg-quick up handle user connection={response}", flush=True)
                user_conn.is_connected = True
                self._conn_count += 1

                print(f"Testing location + ip...", flush=True)
                new_location = get_location()
                print(f"New location: {new_location=}", flush=True)

    def _handle_connection_request(self, acc: ProviderAccount):
        for r in acc.info.requests:
            print(f"New connection request {r=}", flush=True)
            if r.uid == self._server_uid and str(r.requester) not in self._connections:
                print(f"Found connection request", flush=True)
                # assume automatically connected after information is sent over
                conn_context = ConnectionContext(mode="provider",
                                                 pk=PrivateKey.generate(),
                                                 wg_keypair=WireguardIfc.generate_keypair(),
                                                 other_end_solana_pubk=r.requester,
                                                 is_connected=True,
                                                 init_time=time.time())

                # See post_connection_request to see how the bytes are packed
                user_wg_pub_key = base64.b64encode(bytes(r.wg_and_box_pubkey[:32])).decode()
                user_box_pub_key = PublicKey(bytes(r.wg_and_box_pubkey[32:]))

                conn_context.other_end_wg_pubk = user_wg_pub_key
                conn_context.other_end_box_pubk = user_box_pub_key

                server_vpn_ip, user_vpn_ip = self._allocate_ips()
                conn_context.my_vpn_ip = server_vpn_ip
                conn_context.other_end_vpn_ip = user_vpn_ip
                conn_context.server_public_ip = get_public_ip()
                conn_context.default_interface = get_default_route_interface()
                conn_context.wg_ifc = f"wg{self._conn_count}"  # TODO: allocate wireguard interfaces intelligently
                conn_context.port = 51820  # TODO: maybe random ports too eventually?
                conn_context.uid = self._server_uid

                # Build wireguard configuration file and save
                wg_config_file = self._server_wg_fcontents(conn_context, conn_context.wg_ifc)
                config_fpath = self._format_wg_conf_file(conn_context.wg_ifc)

                # Save file and bringup wireguard configuration
                with open(config_fpath, "w") as f:
                    f.write(wg_config_file)

                # TODO: error handling here...
                response = WireguardIfc.wg_quick_up(config_fpath)
                print(f"response from wg-quick up handle connection request={response}", flush=True)
                self._conn_count += 1

                # Send back encrypted info using libsodium box
                print(f"Sending accept connection wireguard_config={conn_context.wg_keypair}", flush=True)

                box = Box(conn_context.pk, conn_context.other_end_box_pubk)

                # encrypted payload: 0-31: wg pub key, 32-35: server public ip, 36-39: user vpn ip
                # total encrypted payload is 80 bytes
                wg_pubk_bytes = base64.b64decode(conn_context.wg_keypair[1])
                server_pub_ip_bytes = int.to_bytes(int(conn_context.server_public_ip), 4, "little")
                user_vpn_ip_bytes = int.to_bytes(int(conn_context.other_end_vpn_ip), 4, "little")
                payload = wg_pubk_bytes + server_pub_ip_bytes + user_vpn_ip_bytes
                encrypted = box.encrypt(payload)

                # payload on-chain is 32 byte box public key, 80 bytes of encrypted payload, and 16 bytes of padding
                payload = bytes(conn_context.pk.public_key) + encrypted + bytes(16)
                response = self._vpn_registry.accept_connection_request(payload, str(r.requester))

                print(f"Sent connection accept: "
                      f"server_ip={conn_context.server_public_ip}, "
                      f"user_vpn_ip={conn_context.other_end_vpn_ip}, "
                      f"wg_public_key={conn_context.wg_keypair[1]},"
                      f"server_public_ip={conn_context.server_public_ip}", flush=True)

                self._connections[str(conn_context.other_end_solana_pubk)] = conn_context

    def _format_wg_conf_file(self, wf_ifc: str):
        return os.path.join(self.WG_FILE_LOCATION, f"{wf_ifc}.conf")

    @staticmethod
    def _server_wg_fcontents(context: ConnectionContext, wg_ifc_name: str) -> str:
        """Returns the file contents for a server given a connection context."""
        return WireguardServerConfig(
            private_key=context.wg_keypair[0],
            my_vpn_ip=str(context.my_vpn_ip),
            wg_interface=context.wg_ifc,
            external_ifc=context.default_interface,
            port=context.port,
            public_key=context.other_end_wg_pubk,
            allowed_ips=str(context.other_end_vpn_ip)
        ).generate_file_contents()

    def _allocate_ips(self) -> Tuple[IPv4Address, IPv4Address]:
        # TODO: we should make sure there's no overlap here with other vpns
        server_vpn_ip = IPv4Address("10.0.0.1")
        user_vpn_ip = IPv4Address("10.0.0.2")
        return server_vpn_ip, user_vpn_ip

    def provider_status(self) -> ProviderStatusResponse:
        return ProviderStatusResponse(is_provider=self.is_provider())
