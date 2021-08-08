import pydantic
from typing import List

from solana.system_program import SYS_PROGRAM_ID
from solana.sysvar import SYSVAR_RENT_PUBKEY

from anchorpy.public_key import PublicKey

from anchorpy.program.namespace.account import AccountDoesNotExistError
from anchorpy.provider import Provider

from anchorpy.program import Program


class ServerInfo(pydantic.BaseModel):
    uid: int
    lat: float
    long: float


class PendingConnectionRequest(pydantic.BaseModel):
    requester: str
    uid: int
    wg_and_box_pubkey: List[int]


class ConnectionStatus(pydantic.BaseModel):
    user: str
    uid: int
    conn_data: List[int]


class ProviderInfo(pydantic.BaseModel):
    authority: str
    servers: List[ServerInfo]
    requests: List[PendingConnectionRequest]
    connections: List[ConnectionStatus]

    class Config:
        schema_extra = {
            "example": {
                "authority": "abc",
                "servers": "",
                "requests": ""
            }
        }


class ProviderAccount(pydantic.BaseModel):
    address: str
    info: ProviderInfo

    class Config:
        schema_extra = {
            "example": {
                "address": "abc",
                "info": ProviderInfo.Config.schema_extra
            }
        }


class CreateProviderAccountResponse(pydantic.BaseModel):
    success: bool
    account: str
    tx_id: str = ""
    msg: str = ""


class RegisterServerResponse(pydantic.BaseModel):
    success: bool
    uid: int
    latitude: float
    longitude: float
    tx_id: str = ""
    msg: str = ""


class VpnRegistry(object):
    def __init__(self, program: Program):
        self._program = program

    @property
    def provider(self) -> Provider:
        return self._program.provider

    @property
    def public_key(self) -> str:
        return str(self._program.provider.wallet.public_key)

    def all_providers(self) -> List[ProviderAccount]:
        providers = list()
        all_providers = self._program.account.provider.all()
        for acc in all_providers:
            provider_info = ProviderInfo(authority=str(acc["account"].authority),
                                         servers=[ServerInfo(uid=s.uid, lat=s.lat, long=s.long) for s in
                                                  acc["account"].servers],
                                         requests=[PendingConnectionRequest(requester=str(r.requestOwner),
                                                                            uid=r.uid,
                                                                            wg_and_box_pubkey=r.wgAndBoxPubkey) for r in
                                                   acc["account"].pendingRequests],
                                         connections=[ConnectionStatus(
                                             user=str(c.user),
                                             uid=c.uid,
                                             conn_data=c.connData
                                         ) for c in acc["account"].connections]
                                         )
            providers.append(ProviderAccount(address=str(acc["public_key"]), info=provider_info))
        return providers

    def register_server(self, uid: int, lat: int, long: int) -> bool:
        # TODO: do something with return status
        tx_result = self._program.rpc.registerServer(uid, lat, long, {
            "accounts": {
                "provider": self.provider_associated_addr(),
                "authority": self._program.provider.wallet.public_key
            },
        })
        return True

    def create_provider(self) -> CreateProviderAccountResponse:
        associated_address = self.provider_associated_addr()
        # TODO: do something with return status
        result = self._program.rpc.createProvider({"accounts": {
            "provider": associated_address,
            "authority": self._program.provider.wallet.public_key,
            "rent": SYSVAR_RENT_PUBKEY,
            "systemProgram": SYS_PROGRAM_ID,
        }})

        return CreateProviderAccountResponse(success=True,
                                             account=str(associated_address),
                                             tx_id="foo",
                                             msg="foobar")

    def connect(self, uid: int, connection_payload: bytes, program_id: str, program_id_auth: str):
        # Create private key, make sure the thing we're trying to connect to actually exists, and send request message
        response = self._program.rpc.connectionRequest(uid,
                                                       connection_payload,
                                                       {
                                                           "accounts": {
                                                               "provider": program_id,
                                                               "providerAuth": program_id_auth,
                                                               "authority": self._program.provider.wallet.public_key
                                                           }
                                                       })
        return True

    def disconnect(self, program_id: str, program_auth: str):
        response = self._program.rpc.disconnect({
            "accounts": {
                "provider": program_id,
                "providerAuth": program_auth,
                "authority": self._program.provider.wallet.public_key
            }
        })
        return True

    def accept_connection_request(self, conn_data: bytes, user: str):
        response = self._program.rpc.acceptConnectionRequest(conn_data,
                                                             {
                                                                 "accounts": {
                                                                     "provider": self.provider_associated_addr(),
                                                                     "authority": self._program.provider.wallet.public_key,
                                                                     "user": user
                                                                 }
                                                             })
        return True

    def provider_associated_addr(self) -> PublicKey:
        my_addr = self._program.provider.wallet.public_key
        associated_address = self._program.account.provider.associated_address(my_addr)
        return associated_address

    def does_provider_exist(self, associated_addr: PublicKey) -> bool:
        try:
            self._program.account.provider.fetch(associated_addr)
            return True
        except AccountDoesNotExistError:
            return False

    def get_provider(self, associated_addr: PublicKey) -> ProviderAccount:
        acc = self._program.account.provider.fetch(associated_addr)
        provider_info = ProviderInfo(authority=str(acc.authority),
                                     servers=[ServerInfo(uid=s.uid, lat=s.lat, long=s.long) for s in
                                              acc.servers],
                                     requests=[PendingConnectionRequest(requester=str(r.requestOwner),
                                                                        uid=r.uid,
                                                                        wg_and_box_pubkey=r.wgAndBoxPubkey) for r in
                                               acc.pendingRequests],
                                     connections=[ConnectionStatus(
                                         user=str(c.user),
                                         uid=c.uid,
                                         conn_data=c.connData
                                     ) for c in acc.connections]
                                     )
        return ProviderAccount(address=str(associated_addr), info=provider_info)
