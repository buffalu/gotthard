use anchor_lang::prelude::*;

#[program]
mod vpn_registry {
    use super::*;

    pub fn create_provider(ctx: Context<CreateProvider>) -> ProgramResult {
        ctx.accounts.provider.authority = *ctx.accounts.authority.key;
        ctx.accounts.provider.servers = Vec::with_capacity(10);
        Ok(())
    }

    // Note: with 500 bytes, it currently allows ~37 servers
    pub fn register_server(ctx: Context<RegisterServer>, uid: u128, lat: i32, long: i32) -> ProgramResult {
        ctx.accounts.provider.servers.push(ServerInfo { uid: uid, lat: lat, long: long });
        Ok(())
    }

    pub fn remove_server(ctx: Context<RemoveServer>, uid: u128) -> ProgramResult {
        let mut idx_to_remove = usize::MAX;
        for (idx, s) in ctx.accounts.provider.servers.iter().enumerate() {
            if s.uid == uid {
                idx_to_remove = idx;
                break;
            }
        }
        if idx_to_remove != usize::MAX {
            ctx.accounts.provider.servers.remove(idx_to_remove);
        }
        Ok(())
    }

    pub fn connection_request(ctx: Context<ConnectionRequest>, uid: u128, wg_and_box_pubkey: [u8; 64]) -> ProgramResult {
        for r in ctx.accounts.provider.pending_requests.iter() {
            if r.request_owner == *ctx.accounts.authority.key {
                return Err(RegistryError::DuplicateUserRequest.into());
            }
        }
        ctx.accounts.provider.pending_requests.push(PendingRequest {
            request_owner: *ctx.accounts.authority.key,
            uid: uid,
            wg_and_box_pubkey: wg_and_box_pubkey,
        });
        Ok(())
    }

    pub fn accept_connection_request(ctx: Context<AcceptConnectionRequest>, conn_data: [u8; 128]) -> ProgramResult {
        let mut idx_to_remove = usize::MAX;
        let mut uid: u128 = 0;
        for (idx, r) in ctx.accounts.provider.pending_requests.iter().enumerate() {
            if *ctx.accounts.user.key == r.request_owner {
                idx_to_remove = idx;
                uid = r.uid;
                break;
            }
        }
        if idx_to_remove != usize::MAX {
            ctx.accounts.provider.pending_requests.remove(idx_to_remove);
        } else {
            // raise error that the accepted connection request can't be found
            return Err(RegistryError::NoSuchConnectionRequest.into());
        }

        ctx.accounts.provider.connections.push(ConnectionStatus {
            user: *ctx.accounts.user.key,
            uid: uid,
            conn_data: conn_data,
        });

        Ok(())
    }

    pub fn disconnect(ctx: Context<DisconnectRequest>) -> ProgramResult {
        let mut idx_to_remove = usize::MAX;
        for (idx, c) in ctx.accounts.provider.connections.iter().enumerate() {
            if *ctx.accounts.authority.key == c.user {
                idx_to_remove = idx;
                break;
            }
        }
        if idx_to_remove != usize::MAX {
            ctx.accounts.provider.connections.remove(idx_to_remove);
        } else {
            return Err(RegistryError::NoSuchConnectionRequest.into());
        }
        Ok(())
    }
}

// TODO : permissions need to be evaluated on these... prob jank

#[derive(Accounts)]
pub struct DisconnectRequest<'info> {
    #[account(mut, associated = provider_auth)]
    provider: ProgramAccount<'info, Provider>,
    // owner of provider account
    provider_auth: AccountInfo<'info>,
    #[account(signer)]
    authority: AccountInfo<'info>, // person sending the disconnect
}

#[derive(Accounts)]
pub struct RemoveServer<'info> {
    #[account(mut, associated = authority, belongs_to = authority)]
    provider: ProgramAccount<'info, Provider>,
    #[account(signer)]
    authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct RegisterServer<'info> {
    #[account(mut, associated = authority, belongs_to = authority)]
    provider: ProgramAccount<'info, Provider>,
    #[account(signer)]
    authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CreateProvider<'info> {
    #[account(init, associated = authority, space = 5000)]
    provider: ProgramAccount<'info, Provider>,
    #[account(signer)]
    authority: AccountInfo<'info>,
    rent: Sysvar<'info, Rent>,
    system_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ConnectionRequest<'info> {
    #[account(mut, associated = provider_auth)]
    provider: ProgramAccount<'info, Provider>,
    provider_auth: AccountInfo<'info>,
    #[account(signer)]
    authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct AcceptConnectionRequest<'info> {
    #[account(mut, associated = authority, belongs_to = authority)]
    provider: ProgramAccount<'info, Provider>,
    #[account(signer)]
    authority: AccountInfo<'info>,
    user: AccountInfo<'info>,
}

#[error]
pub enum RegistryError {
    #[msg("This has already been requested")]
    DuplicateUserRequest,
    #[msg("Connection request does not exist")]
    NoSuchConnectionRequest,
}

#[derive(AnchorSerialize, AnchorDeserialize, PartialEq, Default, Copy, Clone)]
pub struct ServerInfo {
    pub uid: u128,
    pub lat: i32,
    pub long: i32,
}

#[derive(AnchorSerialize, AnchorDeserialize, PartialEq, Copy, Clone)]
pub struct PendingRequest {
    pub request_owner: Pubkey,
    pub uid: u128,
    pub wg_and_box_pubkey: [u8; 64], // NOTE: something weird about having two separate [u8; 32] arrays?
}

#[derive(AnchorSerialize, AnchorDeserialize, PartialEq, Copy, Clone)]
pub struct ConnectionStatus {
    pub user: Pubkey,
    pub uid: u128,
    // [0:32] : provider's box public key used to encrypt the rest
    // [32:112] : encrypted payload which after decryption has the following layout after decryption
    pub conn_data: [u8; 128],
}

#[associated]
pub struct Provider {
    pub authority: Pubkey,
    pub servers: Vec<ServerInfo>,
    pub pending_requests: Vec<PendingRequest>,
    pub connections: Vec<ConnectionStatus>,
}
