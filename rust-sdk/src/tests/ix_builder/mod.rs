use super::*;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use common::*;
use litesvm::{types::TransactionMetadata, LiteSVM};
use litesvm_token::spl_token;
use solana_program::{pubkey::Pubkey, system_program};
use solana_sdk::{
    account::ReadableAccount,
    clock::Clock,
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_interface::{
    program_id, AuthorityConfig, ClientAction, CreateInstruction, CreateSessionInstruction,
    SignInstruction,
};
use swig_state_x::{
    action::{
        all::All, manage_authority::ManageAuthority, program_scope::ProgramScope,
        sol_limit::SolLimit, sol_recurring_limit::SolRecurringLimit,
    },
    authority::{
        ed25519::{CreateEd25519SessionAuthority, ED25519Authority, Ed25519SessionAuthority},
        secp256k1::{
            CreateSecp256k1SessionAuthority, Secp256k1Authority, Secp256k1SessionAuthority,
        },
        AuthorityType,
    },
    role::Role,
    swig::{swig_account_seeds, SwigWithRoles},
    IntoBytes,
};

use super::*;
use crate::{
    error::SwigError, instruction_builder::AuthorityManager, types::Permission, RecurringConfig,
    SwigInstructionBuilder, SwigWallet,
};

pub mod authority_tests;
pub mod program_scope_tests;
pub mod session_tests;
pub mod sub_account_test;
pub mod swig_account_tests;
pub mod transfer_tests;
