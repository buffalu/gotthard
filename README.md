# Gotthard Tunnel

##About
- Peer to peer VPN implementation running on Solana.
- Uses wireguard and a python application with an HTTP server that allows user to configure the application.

## Setup
- Setup instructions are a bit scarce right now and janky from not investing in proper infra setup.
- Setup a virtual env and install pip requirements.
- Setup the OS environment variables.
- Build the vpn_registry using `anchor build && anchor deploy`

## Gotchas
- New private key is generated everytime the application is started.
- This is hackathon quality software, the quality of it shows. Use at your own risk. Not 100% functional.
