import base64

import base58
from nacl.public import Box, PrivateKey, PublicKey
from solana.account import Account

from wg.wg_ifc import WireguardIfc


def main():
    provider_acc = Account()
    provider_pubkey = provider_acc.public_key()

    user_acc = Account()
    user_pubkey = user_acc.public_key()

    provider_pk = PrivateKey(provider_acc.secret_key())
    user_pk = PrivateKey(user_acc.secret_key())

    # wg_priv_key, wg_pub_key = WireguardIfc.generate_keypair()

    user_box = Box(user_pk, PublicKey(bytes(provider_acc.public_key())))
    provider_box = Box(provider_pk, PublicKey(bytes(user_acc.public_key())))

    user_box.encrypt(b"foo")

    # We want provider_pk.public_key to equal provider_acc.public_key() but it seems like that won't work



if __name__ == '__main__':
    main()
