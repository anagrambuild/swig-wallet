use solana_client::{rpc_client::RpcClient, rpc_request::TokenAccountsFilter};
use solana_program::{instruction::Instruction, pubkey::Pubkey};
use solana_sdk::{
    account::ReadableAccount,
    commitment_config::CommitmentConfig,
    message::{v0, VersionedMessage},
    rent::Rent,
    signature::{Keypair, Signer},
    transaction::{Transaction, VersionedTransaction},
};
use swig_state_x::{
    action::{all::All, manage_authority::ManageAuthority, sol_limit::SolLimit},
    authority::AuthorityType,
    role::Role,
    swig::SwigWithRoles,
};

use swig_interface::swig_key;

use crate::{
    error::SwigError,
    instruction_builder::SwigInstructionBuilder,
    types::{Permission, WalletAuthority},
};

pub struct SwigWallet {
    /// The underlying instruction builder
    instruction_builder: SwigInstructionBuilder,
    /// RPC client for interacting with the Solana network
    rpc_client: RpcClient,
    /// The wallet's fee payer
    fee_payer: Keypair,
}

impl SwigWallet {
    /// Creates a new SwigWallet instance
    ///
    /// # Arguments
    /// * `rpc_url` - The URL of the Solana RPC endpoint
    /// * `swig_account` - The public key of the Swig account
    /// * `authority` - The wallet's authority credentials
    /// * `fee_payer` - The keypair that will pay for transactions
    /// * `role_id` - The role id for this wallet
    pub fn new(
        rpc_url: &str,
        swig_id: String,
        authority: WalletAuthority,
        fee_payer: Keypair,
        role_id: u32,
    ) -> Self {
        let swig_account = swig_key(swig_id);

        let rpc_client =
            RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());

        let instruction_builder =
            SwigInstructionBuilder::new(swig_account, authority, fee_payer.pubkey(), role_id);

        Self {
            instruction_builder,
            rpc_client,
            fee_payer,
        }
    }

    /// Loads an existing Swig wallet from chain using its ID
    ///
    /// # Arguments
    /// * `rpc_url` - The URL of the Solana RPC endpoint
    /// * `id` - The unique identifier of the Swig wallet
    /// * `authority` - The authority credentials to use with this wallet
    /// * `fee_payer` - The keypair that will pay for transactions
    pub fn load_from_chain(
        &self,
        swig_id: String,
        authority: WalletAuthority,
    ) -> Result<(), SwigError> {
        let swig_key = swig_key(swig_id);
        let swig_data = self.rpc_client.get_account_data(&swig_key)?;

        let swig_with_roles =
            SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

        // Look up the role ID for this authority
        let role_id = match authority {
            WalletAuthority::Ed25519(authority) => swig_with_roles
                .lookup_role_id(authority.as_ref())
                .map_err(|_| SwigError::AuthorityNotFound)?,
            WalletAuthority::Secp256k1(authority) => swig_with_roles
                .lookup_role_id(authority.as_ref())
                .map_err(|_| SwigError::AuthorityNotFound)?,
        }
        .ok_or(SwigError::AuthorityNotFound)?;

        // Get the role to verify it exists and has the correct type
        let role = swig_with_roles
            .get_role(role_id)
            .map_err(|_| SwigError::AuthorityNotFound)?;

        if let Some(role) = role {
            println!("Role found: {:?}", role.actions);
            Ok(())
        } else {
            Err(SwigError::AuthorityNotFound)
        }
    }

    /// Creates a new Swig wallet account
    ///
    /// # Arguments
    /// * `authority_type` - The type of authority for the new account
    /// * `authority` - The authority string (base58 for Ed25519, hex for Secp256k1)
    /// * `id` - A unique identifier for the account
    pub fn create_wallet(
        &self,
        authority_type: AuthorityType,
        authority: String,
        id: [u8; 32],
    ) -> Result<String, SwigError> {
        let instruction = self.instruction_builder.create_swig_account_instruction(
            authority_type,
            authority,
            self.fee_payer.pubkey(),
            id,
        )?;
        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &[instruction],
            &[],
            self.rpc_client.get_latest_blockhash()?,
        )
        .unwrap();
        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[self.fee_payer.insecure_clone()],
        )
        .unwrap();

        self.send_and_confirm_transaction(tx)
    }

    /// Adds a new authority to the wallet
    ///
    /// # Arguments
    /// * `new_authority_type` - The type of the new authority
    /// * `new_authority` - The new authority's credentials
    /// * `permissions` - Vector of permissions to grant to the new authority
    pub fn add_authority(
        &self,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        permissions: Vec<Permission>,
    ) -> Result<String, SwigError> {
        let instruction = self.instruction_builder.add_authority_instruction(
            new_authority_type,
            new_authority,
            permissions,
        )?;
        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &[instruction],
            &[],
            self.rpc_client.get_latest_blockhash()?,
        )
        .unwrap();

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[self.fee_payer.insecure_clone()],
        )
        .unwrap();

        self.send_and_confirm_transaction(tx)
    }

    /// Removes an authority from the wallet
    ///
    /// # Arguments
    /// * `authority_id` - The ID of the authority to remove
    pub fn remove_authority(&self, authority_id: u32) -> Result<String, SwigError> {
        let instruction = self.instruction_builder.remove_authority(authority_id)?;
        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &[instruction],
            &[],
            self.rpc_client.get_latest_blockhash()?,
        )
        .unwrap();
        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[self.fee_payer.insecure_clone()],
        )
        .unwrap();

        self.send_and_confirm_transaction(tx)
    }
    /// Replaces an existing authority
    ///
    /// # Arguments
    /// * `authority_to_replace_id` - The ID of the authority to replace
    /// * `new_authority_type` - The type of the new authority
    /// * `new_authority` - The new authority's credentials
    /// * `permissions` - Vector of permissions to grant to the new authority
    pub fn replace_authority(
        &self,
        authority_to_replace_id: u32,
        new_authority_type: AuthorityType,
        new_authority: &[u8],
        permissions: Vec<Permission>,
    ) -> Result<String, SwigError> {
        let instructions = self.instruction_builder.replace_authority(
            authority_to_replace_id,
            new_authority_type,
            new_authority,
            permissions,
        )?;

        let msg = v0::Message::try_compile(
            &self.fee_payer.pubkey(),
            &instructions,
            &[],
            self.rpc_client.get_latest_blockhash()?,
        )
        .unwrap();
        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(msg),
            &[self.fee_payer.insecure_clone()],
        )
        .unwrap();

        self.send_and_confirm_transaction(tx)
    }

    /// Signs and executes a transaction with the given instructions
    ///
    /// # Arguments
    /// * `instructions` - The instructions to include in the transaction
    fn send_and_confirm_transaction(&self, tx: VersionedTransaction) -> Result<String, SwigError> {
        // Send and confirm the transaction
        let signature = self.rpc_client.send_and_confirm_transaction(&tx)?;
        Ok(signature.to_string())
    }

    /// Returns the public key of the Swig account
    pub fn get_swig_account(&self) -> Result<Pubkey, SwigError> {
        self.instruction_builder.get_swig_account()
    }

    /// Print the Swig account
    pub fn print_swig_account(&self) -> Result<(), SwigError> {
        let swig_account = self.get_swig_account()?;
        println!("Swig account: {:?}", swig_account);
        Ok(())
    }

    pub fn diplay_swig(&self, swig_pubkey: Pubkey, authority_id: u32) -> Result<(), SwigError> {
        let swig_account = self.rpc_client.get_account(&swig_pubkey)?;

        let swig_data = self.rpc_client.get_account_data(&swig_pubkey)?;
        let swig_with_roles =
            SwigWithRoles::from_bytes(&swig_data).map_err(|e| SwigError::InvalidSwigData)?;

        println!("\tKEY: {}", swig_pubkey);
        println!(
            "\tID: {}",
            String::from_utf8(swig_with_roles.state.id.to_vec()).unwrap()
        );
        println!(
            "\tLamports: {}",
            swig_account.lamports() //- Rent::default().minimum_balance(swig_with_roles)
        );

        let role = swig_with_roles
            .get_role(authority_id)
            .map_err(|e| SwigError::AuthorityNotFound)?;
        if let Some(role) = role {
            println!("\tRole {}", authority_id);
            println!("\t\tAuthority Type: {:?}", role.authority.authority_type());
            println!(
                "\t\tAuthority: {:?}",
                match role.authority.authority_type() {
                    AuthorityType::Ed25519 => "Ed25519".to_string(), //bs58::encode(role.authority.as_slice()).into_string(),
                    AuthorityType::Secp256k1 => "Secp256k1".to_string(), //hex::encode(role.authority.as_slice()),
                    _ => todo!(),
                }
            );
            println!("\tPosition: {:?}", role.position);

            println!("\t\tPermissions:");

            // All
            if let Some(_) =
                Role::get_action::<All>(&role, &[]).map_err(|_| SwigError::AuthorityNotFound)?
            {
                println!("\t\tAll permission exists");
            }
            // Sol Limit
            if let Some(action) = Role::get_action::<SolLimit>(&role, &[])
                .map_err(|_| SwigError::AuthorityNotFound)?
            {
                println!("\t\tSol Limit {:?}", action);
            }
            // Manage Authority
            if let Some(_) = Role::get_action::<ManageAuthority>(&role, &[])
                .map_err(|_| SwigError::AuthorityNotFound)?
            {
                println!("\t\tManage Authority permission exists");
            }
        }

        // let token_accounts = self.rpc_client.get_token_accounts_by_owner(
        //     &swig_id,
        //     TokenAccountsFilter::ProgramId(TOKEN_PROGRAM_ID),
        // )?;
        // let token_accounts_22 = self.rpc_client.get_token_accounts_by_owner(
        //     &swig_id,
        //     TokenAccountsFilter::ProgramId(TOKEN_22_PROGRAM_ID),
        // )?;
        // if !token_accounts.is_empty() || !token_accounts_22.is_empty() {
        //     println!("\tToken Accounts:");
        // }
        // for (index, token_account) in token_accounts.iter().enumerate() {
        //     if let UiAccountData::Json(ParsedAccount {
        //         program, parsed, ..
        //     }) = &token_account.account.data
        //     {
        //         println!("\t\tKey: {}", token_account.pubkey);
        //         println!("\t\tMint: {}", parsed["info"]["mint"].as_str().unwrap());
        //         println!("\t\tAmount: {}", parsed["info"]["tokenAmount"]["uiAmount"]);
        //     }
        // }
        // for (index, token_account) in token_accounts_22.iter().enumerate() {
        //     if let UiAccountData::Json(ParsedAccount {
        //         program, parsed, ..
        //     }) = &token_account.account.data
        //     {
        //         println!("\t\tKey: {}", token_account.pubkey);
        //         println!("\t\tMint: {}", parsed["info"]["mint"].as_str().unwrap());
        //         println!("\t\tAmount: {}", parsed["info"]["tokenAmount"]["uiAmount"]);
        //     }
        // }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::pubkey::Pubkey;
    use solana_sdk::signature::Keypair;
    use swig_state_x::authority::AuthorityType;

    // Helper function to setup a test wallet
    fn setup_test_wallet() -> SwigWallet {
        let rpc_url = "http://localhost:8899".to_string(); // Local testnet URL
        let swig_id = "test_swig".to_string();
        let fee_payer = Keypair::new();

        // Create an Ed25519 authority for testing
        let authority_keypair = Keypair::new();
        let authority = WalletAuthority::Ed25519(authority_keypair.pubkey());

        SwigWallet::new(
            &rpc_url, swig_id, authority, fee_payer, 1, // role_id
        )
    }

    #[test]
    fn test_create_wallet() {
        let wallet = setup_test_wallet();

        let authority_type = AuthorityType::Ed25519;
        let authority_keypair = Keypair::new();
        let authority = bs58::encode(authority_keypair.pubkey().to_bytes()).into_string();
        let id = [0u8; 32];

        // request airdrop for the authority
        let airdrop_signature = wallet
            .rpc_client
            .request_airdrop(&authority_keypair.pubkey(), 2_000_000_000)
            .unwrap();
        wallet
            .rpc_client
            .confirm_transaction(&airdrop_signature)
            .unwrap();

        println!("Creating wallet with authority: {:?}", authority);
        match wallet.create_wallet(authority_type, authority, id) {
            Ok(signature) => {
                assert!(
                    !signature.is_empty(),
                    "Transaction signature should not be empty"
                );
            },
            Err(e) => panic!("Failed to create wallet: {:?}", e),
        }
    }

    #[test]
    fn test_add_authority() {
        let wallet = setup_test_wallet();

        let new_authority_type = AuthorityType::Ed25519;
        let new_authority = &[1u8; 32]; // Example authority bytes
        let permissions = vec![Permission::All];

        match wallet.add_authority(new_authority_type, new_authority, permissions) {
            Ok(signature) => {
                assert!(
                    !signature.is_empty(),
                    "Transaction signature should not be empty"
                );
            },
            Err(e) => panic!("Failed to add authority: {:?}", e),
        }
    }

    #[test]
    fn test_remove_authority() {
        let wallet = setup_test_wallet();

        match wallet.remove_authority(1) {
            Ok(signature) => {
                assert!(
                    !signature.is_empty(),
                    "Transaction signature should not be empty"
                );
            },
            Err(e) => panic!("Failed to remove authority: {:?}", e),
        }
    }

    #[test]
    fn test_replace_authority() {
        let wallet = setup_test_wallet();

        let new_authority_type = AuthorityType::Ed25519;
        let new_authority = &[2u8; 32]; // Example authority bytes
        let permissions = vec![Permission::Sol {
            amount: 1000000000,
            recurring: None,
        }];

        match wallet.replace_authority(1, new_authority_type, new_authority, permissions) {
            Ok(signature) => {
                assert!(
                    !signature.is_empty(),
                    "Transaction signature should not be empty"
                );
            },
            Err(e) => panic!("Failed to replace authority: {:?}", e),
        }
    }

    #[test]
    fn test_get_swig_account() {
        let wallet = setup_test_wallet();

        println!("Swig account: {:?}", wallet.get_swig_account());

        println!(
            "Displaying swig account: {:?}",
            wallet.get_swig_account().unwrap()
        );

        wallet
            .diplay_swig(wallet.get_swig_account().unwrap(), 0)
            .unwrap();

        match wallet.get_swig_account() {
            Ok(pubkey) => {
                assert_ne!(
                    pubkey,
                    Pubkey::default(),
                    "Swig account should not be default pubkey"
                );
            },
            Err(e) => panic!("Failed to get swig account: {:?}", e),
        }
    }
}
