import pydantic
from fastapi import APIRouter

from app.vpn_registry import CreateProviderAccountResponse
from app.runner import app_runner_singleton

# Routes for anything blockchain related
account_router = APIRouter(prefix="/account")
app_runner = app_runner_singleton()


class AccountBalance(pydantic.BaseModel):
    address: str
    balance: float


@account_router.get("/balance",
                    description="Returns account balance for this account",
                    response_model=AccountBalance,
                    response_description="The balance of the account")
async def get_balance():
    return AccountBalance(address=str(app_runner.public_key), balance=app_runner.balance())
