import uvicorn
import os, os.path
import pathlib


def main():
    # TODO: this is also pretty hacky
    SCRIPT_DIR = pathlib.Path(__file__).parent.absolute()
    os.environ["IDL_FPATH"] = f"{SCRIPT_DIR}/../sol-vpn/target/idl/vpn_registry.json"
    os.environ["SERVER_PORT"] = "8080"
    os.environ["WEB_SERVER_HOST"] = "0.0.0.0"
    os.environ["WEB3_PROVIDER"] = "VALIDATOR_ENDPOINT_HERE"
    os.environ["AIRDROP_PROVIDER"] = "VALIDATOR_ENDPOINT_HERE"
    os.environ["LOG_CONFIG_FILE"] = f"{SCRIPT_DIR}/log/logging.yaml"

    uvicorn.run("web.server.app:app", host=os.environ.get("WEB_SERVER_HOST"),
                port=int(os.environ["SERVER_PORT"]), reload=True)


if __name__ == '__main__':
    main()
