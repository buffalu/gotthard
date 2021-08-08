import pydantic
from fastapi import APIRouter
from typing import List

from app.connection_manager import PostConnectionResponse, DeleteConnectionResponse, ConnectionStatusResponse, \
    ProviderStatusResponse
from app.vpn_registry import ProviderAccount, CreateProviderAccountResponse, RegisterServerResponse
from app.runner import app_runner_singleton

# Routes for anything blockchain related
vpn_registry_route = APIRouter(prefix="/vpn_registry")
app_runner = app_runner_singleton()


class ConnectionRequest(pydantic.BaseModel):
    program_id: str
    uid: int


@vpn_registry_route.get("/providers",
                        summary="Gets a list of providers available",
                        response_model=List[ProviderAccount],
                        response_description="List of available provider accounts"
                        )
async def get_providers():
    return app_runner.all_providers()


@vpn_registry_route.post("/provider",
                         summary="Creates a provider account",
                         response_model=CreateProviderAccountResponse,
                         response_description="List of available provider accounts"
                         )
async def create_provider():
    return app_runner.create_provider()


@vpn_registry_route.post("/server",
                         summary="Adds this server to the servers available under this provider",
                         response_model=RegisterServerResponse)
async def add_server() -> RegisterServerResponse:
    return app_runner.add_server()


@vpn_registry_route.post("/connection_request",
                         summary="",
                         response_model=PostConnectionResponse
                         )
async def connect_to_server(r: ConnectionRequest):
    print(f"got connection request: {r}", flush=True)
    return app_runner.connect(r.program_id, r.uid)


@vpn_registry_route.delete("/connection",
                           summary="",
                           response_model=DeleteConnectionResponse
                           )
async def disconnect_from_server():
    return app_runner.user_disconnect()


@vpn_registry_route.get("/connection_status",
                        summary="",
                        response_model=ConnectionStatusResponse
                        )
async def connection_status():
    return app_runner.connection_status()


@vpn_registry_route.get("/provider_status",
                        summary="",
                        response_model=ProviderStatusResponse
                        )
async def provider_status():
    return app_runner.provider_status()


app_runner.user_disconnect()
