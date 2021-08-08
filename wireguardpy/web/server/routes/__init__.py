from web.server.database.db import VpnDatabase

db = None


def get_db() -> VpnDatabase:
    global db
    if not db:
        db = VpnDatabase("/tmp/vpn.db")
    return db
