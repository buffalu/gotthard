import threading
from typing import List

import tinydb


class VpnDatabase(object):
    PRIVATE_KEY_TABLE = "private_keys"

    def __init__(self, fpath: str):
        self.fpath = fpath
        self.db = tinydb.TinyDB(self.fpath)

    def __enter__(self):
        self.db.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.db.__exit__()

    def get_private_key(self) -> str:
        priv_key_table = self.db.table(self.PRIVATE_KEY_TABLE)
        all_private_keys = priv_key_table.all()
        return all_private_keys[0]["private_key"] if len(all_private_keys) else ""

    def set_private_key(self, priv_key: str) -> bool:
        # TODO (LB) we should make sure this is stored with a hash + salt eventually
        priv_key_table = self.db.table(self.PRIVATE_KEY_TABLE)
        private_keys = priv_key_table.all()
        if private_keys:
            return False
        priv_key_table.insert({"private_key": priv_key})
        return True

    def remove_private_keys(self) -> bool:
        self.db.drop_table(self.PRIVATE_KEY_TABLE)
        return True
