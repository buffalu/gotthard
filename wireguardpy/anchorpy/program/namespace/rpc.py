from typing import Any, Callable, Dict

from solana.transaction import TransactionSignature

from anchorpy.program.context import split_args_and_context
from anchorpy.idl import IdlInstruction
from anchorpy.provider import Provider
from anchorpy.program.namespace.transaction import TransactionFn
import pprint

RpcFn = Callable[[Any], TransactionSignature]


class RpcNamespace(object):
    pass


class RpcNamespaceFactory(object):
    @staticmethod
    def build(idl_ix: IdlInstruction, tx_fn: TransactionFn, idl_errors: Dict[int, str], provider: Provider) -> RpcFn:
        def rpc_fn(*args: Any) -> TransactionSignature:
            tx = tx_fn(*args)
            args = list(args)
            _, ctx = split_args_and_context(idl_ix, args)
            # try:
            tx_sig = provider.send(tx, ctx.signers, ctx.options)
            return tx_sig["result"]
            # except Exception as e:
            #     # translated_err = translate_err(idl_errors, tx_sig["error"])
            #     # TODO
            #     """
            #     let translatedErr = translateError(idlErrors, err);
            #     if (translatedErr === null) {
            #       throw err;
            #     }
            #     throw translatedErr;
            #     """
            #     print(f"Translating error: {e}", flush=True)

        return rpc_fn
