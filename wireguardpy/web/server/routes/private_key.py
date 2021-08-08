from fastapi import APIRouter

from web.server.routes import get_db

private_key_router = APIRouter(prefix="/private_keys")
db = get_db()

# https://fastapi.tiangolo.com/tutorial/path-params/#path-parameters-with-types
@private_key_router.get("/", response_description="Gets the private key.")
async def get_private_key():
    return db.get_private_key()


@private_key_router.post("/", response_description="Writes a private key.")
async def write_private_key(priv_key: str):
    return db.set_private_key(priv_key)


@private_key_router.delete("/", response_description="Deletes all private keys.")
async def delete_private_kay():
    return db.remove_private_keys()
