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
use swig_interface::swig_key;
use swig_state_x::{
    action::{all::All, manage_authority::ManageAuthority, sol_limit::SolLimit},
    authority::AuthorityType,
    role::Role,
    swig::SwigWithRoles,
};

use crate::{error::SwigError, instruction_builder::SwigInstructionBuilder, types::Permission};

pub struct SwigWallet {
    /// The underlying instruction builder
    instruction_builder: SwigInstructionBuilder,
    /// RPC client for interacting with the Solana network
    pub rpc_client: RpcClient,
    /// The wallet's fee payer
    fee_payer: Keypair,
}

impl SwigWallet {
    /// Creates a new SwigWallet instance
    ///
    /// # Arguments
    /// * `swig_account` - The public key of the Swig account
    /// * `authority` - The wallet's authority credentials
    /// * `fee_payer` - The keypair that will pay for transactions
    /// * `role_id` - The role id for this wallet
    /// * `rpc_url` - The URL of the Solana RPC endpoint
    pub fn new(
        swig_id: [u8; 32],
        authority_type: AuthorityType,
        authority: Pubkey,
        fee_payer: Keypair,
        rpc_url: String,
    ) -> Result<Self, SwigError> {
        let rpc_client =
            RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());

        println!(
            "Balance of fee payer: {:?}",
            rpc_client.get_balance(&fee_payer.pubkey())?
        );

        // Check if the Swig account already exists
        let swig_account = SwigInstructionBuilder::swig_key(&swig_id);
        let swig_data = rpc_client.get_account_data(&swig_account)?;

        if swig_data.is_empty() {
            println!("Swig account does not exist, creating new one");
            let instruction_builder = SwigInstructionBuilder::new(
                swig_id,
                authority_type,
                authority,
                fee_payer.pubkey(),
                0,
            );

            let create_ix = instruction_builder.build_swig_account()?;

            let msg = v0::Message::try_compile(
                &fee_payer.pubkey(),
                &[create_ix],
                &[],
                rpc_client.get_latest_blockhash()?,
            )
            .unwrap();

            let tx = VersionedTransaction::try_new(
                VersionedMessage::V0(msg),
                &[fee_payer.insecure_clone()],
            )
            .unwrap();

            let signature = rpc_client.send_and_confirm_transaction(&tx)?;
            println!("Swig account created");
            println!("Transaction signature: {:?}", signature);

            return Ok(Self {
                instruction_builder,
                rpc_client,
                fee_payer,
            });
        } else {
            println!("Swig account already exists");

            let swig_with_roles =
                SwigWithRoles::from_bytes(&swig_data).map_err(|_| SwigError::InvalidSwigData)?;

            let role_id = match authority_type {
                AuthorityType::Ed25519 => swig_with_roles
                    .lookup_role_id(authority.as_ref())
                    .map_err(|_| SwigError::AuthorityNotFound)?,
                AuthorityType::Secp256k1 => swig_with_roles
                    .lookup_role_id(authority.as_ref())
                    .map_err(|_| SwigError::AuthorityNotFound)?,
                _ => todo!(),
            }
            .ok_or(SwigError::AuthorityNotFound)?;

            // Get the role to verify it exists and has the correct type
            let role = swig_with_roles
                .get_role(role_id)
                .map_err(|_| SwigError::AuthorityNotFound)?;

            if let Some(role) = role {
                println!("Role found: {:?}", role.actions);
            } else {
                println!("Role not found");
            }

            let instruction_builder = SwigInstructionBuilder::new(
                swig_id,
                authority_type,
                authority,
                fee_payer.pubkey(),
                role_id,
            );

            Ok(Self {
                instruction_builder,
                rpc_client,
                fee_payer,
            })
        }
    }

    // /// Loads an existing Swig wallet from chain using its ID
    // ///
    // /// # Arguments
    // /// * `rpc_url` - The URL of the Solana RPC endpoint
    // /// * `id` - The unique identifier of the Swig wallet
    // /// * `authority` - The authority credentials to use with this wallet
    // /// * `fee_payer` - The keypair that will pay for transactions
    // pub fn load(&self, swig_id: [u8; 32], authority_type: AuthorityType) ->
    // Result<(), SwigError> {     let swig_key =
    // SwigInstructionBuilder::swig_key(&swig_id);     let swig_data =
    // self.rpc_client.get_account_data(&swig_key)?;

    //     let swig_with_roles =
    //         SwigWithRoles::from_bytes(&swig_data).map_err(|e|
    // SwigError::InvalidSwigData)?;

    //     // Look up the role ID for this authority
    //     let role_id = match authority_type {
    //         AuthorityType::Ed25519 => swig_with_roles
    //             .lookup_role_id(authority.as_ref())
    //             .map_err(|_| SwigError::AuthorityNotFound)?,
    //         AuthorityType::Secp256k1 => swig_with_roles
    //             .lookup_role_id(authority.as_ref())
    //             .map_err(|_| SwigError::AuthorityNotFound)?,
    //         _ => todo!(),
    //     }
    //     .ok_or(SwigError::AuthorityNotFound)?;

    //     // Get the role to verify it exists and has the correct type
    //     let role = swig_with_roles
    //         .get_role(role_id)
    //         .map_err(|_| SwigError::AuthorityNotFound)?;

    //     if let Some(role) = role {
    //         println!("Role found: {:?}", role.actions);
    //         Ok(())
    //     } else {
    //         Err(SwigError::AuthorityNotFound)
    //     }
    // }

    // /// Creates a new Swig wallet account
    // ///
    // /// # Arguments
    // /// * `authority_type` - The type of authority for the new account
    // /// * `authority` - The authority string (base58 for Ed25519, hex for
    // ///   Secp256k1)
    // /// * `id` - A unique identifier for the account
    // pub fn create_wallet(
    //     &self,
    //     authority_type: AuthorityType,
    //     authority: String,
    //     id: [u8; 32],
    // ) -> Result<String, SwigError> {
    //     let instruction =
    // self.instruction_builder.create_swig_account_instruction(
    //         authority_type,
    //         authority,
    //         self.fee_payer.pubkey(),
    //         id,
    //     )?;
    //     let msg = v0::Message::try_compile(
    //         &self.fee_payer.pubkey(),
    //         &[instruction],
    //         &[],
    //         self.rpc_client.get_latest_blockhash()?,
    //     )
    //     .unwrap();
    //     let tx = VersionedTransaction::try_new(
    //         VersionedMessage::V0(msg),
    //         &[self.fee_payer.insecure_clone()],
    //     )
    //     .unwrap();

    //     println!("Transaction: {:?}", tx);

    //     self.send_and_confirm_transaction(tx)
    // }

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
                    AuthorityType::Ed25519 => "Ed25519".to_string(), // bs58::encode(role.
                    // authority.as_slice()).
                    // into_string(),
                    AuthorityType::Secp256k1 => "Secp256k1".to_string(), // hex::encode(role.
                    // authority.as_slice()),
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
        //         println!("\t\tAmount: {}",
        // parsed["info"]["tokenAmount"]["uiAmount"]);     }
        // }
        // for (index, token_account) in token_accounts_22.iter().enumerate() {
        //     if let UiAccountData::Json(ParsedAccount {
        //         program, parsed, ..
        //     }) = &token_account.account.data
        //     {
        //         println!("\t\tKey: {}", token_account.pubkey);
        //         println!("\t\tMint: {}", parsed["info"]["mint"].as_str().unwrap());
        //         println!("\t\tAmount: {}",
        // parsed["info"]["tokenAmount"]["uiAmount"]);     }
        // }
        Ok(())
    }
}
