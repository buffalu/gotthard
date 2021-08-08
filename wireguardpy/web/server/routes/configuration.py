from fastapi import APIRouter

from app.runner import app_runner_singleton

configuration_router = APIRouter(prefix="/config")
app_runner = app_runner_singleton()


@configuration_router.post("/rpc_endpoint", response_description="Change RPC endpoint")
async def rpc_endpoint(rpc_endpoint: str):
    return True

@configuration_router.get("/rpc_endpoint", response_description="Get the current RPC endpoint")
async def rpc_endpoint():
    return True

