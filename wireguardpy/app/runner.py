import asyncio
import base64
import json
import os
import random
import sys
import traceback
import uuid
from dataclasses import dataclass
from ipaddress import IPv4Address
from types import SimpleNamespace
from typing import Optional, Dict, Tuple, List

from nacl.public import PrivateKey, Box, PublicKey
from solana.rpc.api import Client
from solana.account import Account
from solana.rpc.types import TxOpts

from anchorpy.idl import Idl
from anchorpy.program import Program
from anchorpy.provider import Provider, NodeWallet
from app.connection_manager import ConnectionManager, PostConnectionResponse, ConnectionStatusResponse, \
    ProviderStatusResponse

from app.vpn_registry import CreateProviderAccountResponse, RegisterServerResponse, ProviderAccount, VpnRegistry


def get_provider(acc: Account) -> Provider:
    return Provider(os.environ["WEB3_PROVIDER"],
                    NodeWallet.from_account(acc),
                    TxOpts(skip_confirmation=False,
                           preflight_commitment="confirmed"))  # noqa


def load_program(fpath: str, provider: Provider) -> Program:
    with open(fpath) as f:
        idl = Idl.parse_json(json.loads(f.read()))
    return Program(idl, idl.metadata.address, provider)


class AppRunner(object):
    """Responsible for running all background tasks and holding state for HTTP endpoints and sockets and stuff.."""
    LOCATION_SCALAR = 1000
    PORT = 51820

    def __init__(self):
        self._acc = Account()
        self._provider = get_provider(self._acc)

        self._connection_manager = ConnectionManager(VpnRegistry(load_program(os.environ["IDL_FPATH"], self._provider)))
        self._get_airdrop()

        print(f"Public key: {self.public_key}", flush=True)

    @property
    def connection_manager(self) -> ConnectionManager:
        return self._connection_manager

    @property
    def public_key(self):
        return self._acc.public_key()

    def balance(self) -> float:
        """Returns balance of the account"""
        return self._provider.get_balance(self.public_key)["result"]["value"] * 0.000000001

    def _get_airdrop(self):
        Client(os.environ["AIRDROP_PROVIDER"]).request_airdrop(self._acc.public_key(), int(10 / 0.000000001))

    async def run_loop(self):
        while True:
            await asyncio.sleep(0.1)
            self._connection_manager.manage_connections()

    def create_provider(self) -> CreateProviderAccountResponse:
        return self.connection_manager.post_provider()

    def connect(self, program_id: str, uid: int) -> PostConnectionResponse:
        return self.connection_manager.post_connection_request(program_id, uid)

    def add_server(self) -> RegisterServerResponse:
        return self.connection_manager.post_server_info()

    def all_providers(self) -> List[ProviderAccount]:
        return self.connection_manager.all_providers()

    def user_disconnect(self):
        """We'll just assume only providers want to disconnect now..."""
        return self.connection_manager.user_disconnect()

    def connection_status(self) -> ConnectionStatusResponse:
        return self.connection_manager.connection_status()

    def provider_status(self) -> ProviderStatusResponse:
        return self.connection_manager.provider_status()


app_runner = None


def app_runner_singleton() -> AppRunner:
    """
    Returns AppRunner instance, there should only be one global instance of this.
    """
    global app_runner
    if not app_runner:
        app_runner = AppRunner()
    return app_runner
