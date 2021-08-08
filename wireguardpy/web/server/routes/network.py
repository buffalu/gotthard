from fastapi import APIRouter

from networking.network import get_public_ip, get_location

network_router = APIRouter(prefix="/network")


@network_router.get("/public_ip",
                    response_description="Gets the public IP address")
async def public_ip():
    return {"ip": str(get_public_ip())}


@network_router.get("/location",
                    response_description="Gets the location using the IP address")
async def location():
    return get_location()
