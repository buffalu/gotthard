import asyncio
import os

from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi import FastAPI, Request

from log.logger import setup_logging
from web.server.routes.account import account_router
from web.server.routes.network import network_router
from web.server.routes.app_state import app_state_router
from web.server.routes.configuration import configuration_router
from web.server.routes.private_key import private_key_router
from app.runner import app_runner_singleton

from web.server.routes.vpn_registry import vpn_registry_route

app = FastAPI(debug=True)

# API calls (called from frontend)
app.include_router(private_key_router, tags=["Private Key"], prefix="/api/v1")
app.include_router(vpn_registry_route, tags=["User API"], prefix="/api/v1")
app.include_router(configuration_router, tags=["Configuration API"], prefix="/api/v1")
app.include_router(network_router, tags=["Network API"], prefix="/api/v1")
app.include_router(app_state_router, tags=["Application State"], prefix="/api/v1")
app.include_router(account_router, tags=["Account Info"], prefix="/api/v1")

templates = Jinja2Templates(directory="web/server/templates")


@app.on_event('startup')
async def app_startup():
    setup_logging(os.environ["LOG_CONFIG_FILE"])
    asyncio.create_task(app_runner_singleton().run_loop())


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
