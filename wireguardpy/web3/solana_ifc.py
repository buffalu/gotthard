from solana.account import Account
from solana.blockhash import Blockhash
from solana.message import Message, MessageArgs, MessageHeader
from solana.publickey import PublicKey
from solana.rpc.api import Client
from solana.rpc.commitment import Max
from solana.transaction import Transaction
from spl.token.instructions import transfer, TransferParams


class SolanaIfc(object):
    def __init__(self, url: str = "http://localhost:8899"):
        self.client = Client(url)

    def is_connected(self) -> bool:
        return self.client.is_connected()


url = "http://localhost:8899"
program_id = "9LjETnH9fyPWosoUVXrvmFvy7X3VAuydyfmd5UuNRwFL"


client = Client(url)
print(f"Client connected: {client.is_connected()}")
recent_blockhash = client.get_recent_blockhash(Max)["result"]["value"]["blockhash"]
print(f"Recent blockhash: {recent_blockhash}")

client.get_account_info(program_id, encoding="jsonParsed")

#
# acc1 = Account(bytes([8] * 32))
# tx = client.request_airdrop(acc1.public_key(), 1000000)
# acc2_pubkey = PublicKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri")
# tx = Transaction().add(transfer(
#     TransferParams(from_pubkey=acc1.public_key(), to_pubkey=acc2_pubkey, lamports=1000000)))
# tx.recent_blockhash = Blockhash(recent_blockhash["result"]["value"]["blockhash"])
# tx.sign(acc1)
# solana_client.simulate_transaction(tx)
#
#
