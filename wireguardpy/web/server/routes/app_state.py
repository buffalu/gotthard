from fastapi import APIRouter

from app.vpn_registry import CreateProviderAccountResponse
from app.runner import app_runner_singleton

# Routes for anything blockchain related
app_state_router = APIRouter(prefix="/app_state")
app_runner = app_runner_singleton()


@app_state_router.get("/user_state",
                      response_description="Gets state of user state machine")
async def user_state():
    return {"user_state": app_runner.user_state_machine.state}


@app_state_router.get("/provider_state",
                      response_description="Gets state of provider state machine")
async def provider_state():
    return {"provider_state": app_runner.provider_state_machine.state}
