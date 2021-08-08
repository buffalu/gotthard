import time

import requests
import pprint


class VpnRegisteryApi(object):
    def __init__(self, url: str):
        self.url = url

    def get_providers(self):
        return requests.get(f"{self.url}/api/v1/vpn_registry/providers")

    def get_balance(self):
        return requests.get(f"{self.url}/api/v1/account/balance").json()

    def create_provider_account(self):
        return requests.post(f"{self.url}/api/v1/vpn_registry/provider")

    def register_server(self):
        return requests.post(f"{self.url}/api/v1/vpn_registry/server").json()

    def connect(self, uid: int, program_id: str):
        return requests.post(f"{self.url}/api/v1/vpn_registry/connection_request",
                             json={"uid": uid, "program_id": program_id}).json()

    def disconnect(self):
        return requests.delete(f"{self.url}/api/v1/vpn_registry/connection").json()


def wait_for_balanaces(api):
    p_balance = api.get_balance()
    while p_balance["balance"] == 0:
        print("waiting for balance to not be 0...")
        p_balance = api.get_balance()
        time.sleep(1.0)


USER_WEB_SERVER = "http://localhost:8080"
PROVIDER_WEB_SERVER = ""

user = VpnRegisteryApi(USER_WEB_SERVER)

user.get_providers()









provider = VpnRegisteryApi(PROVIDER_WEB_SERVER)

wait_for_balanaces(user)
p_create_resp = provider.create_provider_account()
p_reg_server_resp = provider.register_server()

provider_addr = provider.get_balance()["address"]
# print(f"Providers: {user.get_providers()}", flush=True)

uid = None
program_id = None
for d in user.get_providers():
    if d["info"]["authority"] == provider_addr:
        program_id = d["address"]
        uid = d["info"]["servers"][0]["uid"]
        break

print(f"Connecting to uid={uid}, program_id={program_id}", flush=True)
connect_response = user.connect(uid, program_id)
