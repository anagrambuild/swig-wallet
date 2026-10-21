#![allow(dead_code)]

use developer_account_registry::error::DeveloperAccountRegistryError;
pub use developer_account_registry_interface::{
    developer_account_address, program_id, registry_admin,
    CreateOrUpdateDeveloperAccountInstruction, DeveloperAccount, DeveloperTier,
};
use litesvm::LiteSVM;
pub use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    transaction::TransactionError,
};
use solana_sdk::{
    message::{v0, VersionedMessage},
    transaction::VersionedTransaction,
};

pub const PROGRAM_PATH: &str = "../target/deploy/developer_account_registry.so";

pub const FEE_PER_SIGNATURE: u64 = 5_000;

pub struct RegistryTestContext {
    pub svm: LiteSVM,
    pub payer: Keypair,
}

// `REGISTRY_ADMIN` has no private key in tests, so signatures are not
// verified; the program still checks the admin key and its signer flag.
pub fn setup_test_context() -> RegistryTestContext {
    let mut svm = LiteSVM::new().with_sigverify(false);
    svm.add_program_from_file(program_id(), PROGRAM_PATH)
        .expect("build the registry with cargo build-sbf first");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    svm.airdrop(&registry_admin(), 10_000_000_000).unwrap();
    RegistryTestContext { svm, payer }
}

pub fn send_from(
    context: &mut RegistryTestContext,
    fee_payer: &Pubkey,
    instruction: Instruction,
) -> Result<(), TransactionError> {
    assert!(!context.svm.get_sigverify());
    context.svm.expire_blockhash();
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            fee_payer,
            &[instruction],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let signatures =
        vec![Signature::default(); usize::from(message.header().num_required_signatures)];
    context
        .svm
        .send_transaction(VersionedTransaction {
            signatures,
            message,
        })
        .map(|_| ())
        .map_err(|e| {
            eprintln!("{}", e.meta.pretty_logs());
            e.err
        })
}

pub fn send(
    context: &mut RegistryTestContext,
    instruction: Instruction,
) -> Result<(), TransactionError> {
    let payer = context.payer.pubkey();
    send_from(context, &payer, instruction)
}

pub fn assert_registry_error(
    result: Result<(), TransactionError>,
    expected: DeveloperAccountRegistryError,
) {
    assert_instruction_error(result, InstructionError::Custom(expected as u32));
}

pub fn assert_instruction_error(result: Result<(), TransactionError>, expected: InstructionError) {
    match result {
        Ok(()) => panic!("expected {expected:?}, but the transaction succeeded"),
        Err(error) => assert_eq!(error, TransactionError::InstructionError(0, expected)),
    }
}

pub fn random_id() -> [u8; 32] {
    rand::random::<[u8; 32]>()
}

pub fn create_or_update_ix(
    context: &RegistryTestContext,
    id: [u8; 32],
    tier: DeveloperTier,
    valid_until: i64,
) -> Instruction {
    let (address, _) = developer_account_address(&id);
    CreateOrUpdateDeveloperAccountInstruction::new(
        address,
        registry_admin(),
        context.payer.pubkey(),
        id,
        tier,
        valid_until,
    )
    .unwrap()
}

pub fn create_account(context: &mut RegistryTestContext, id: [u8; 32]) -> Pubkey {
    let ix = create_or_update_ix(context, id, DeveloperTier::Pro, 2_000_000_000);
    send(context, ix).unwrap();
    developer_account_address(&id).0
}

pub fn account(context: &RegistryTestContext, address: &Pubkey) -> Option<Account> {
    context.svm.get_account(address)
}

pub fn lamports(context: &RegistryTestContext, address: &Pubkey) -> u64 {
    account(context, address).map(|a| a.lamports).unwrap_or(0)
}

pub fn rent(context: &RegistryTestContext, len: usize) -> u64 {
    context.svm.minimum_balance_for_rent_exemption(len)
}

pub fn overwrite_data(context: &mut RegistryTestContext, address: &Pubkey, data: Vec<u8>) {
    let mut existing = account(context, address).unwrap();
    existing.data = data;
    context.svm.set_account(*address, existing).unwrap();
}

pub fn expected_image(id: [u8; 32], tier: DeveloperTier, valid_until: i64) -> Vec<u8> {
    let (_, bump) = developer_account_address(&id);
    let mut image = vec![1, 1, bump, tier as u8, 0, 0, 0, 0];
    image.extend_from_slice(&id);
    image.extend_from_slice(&[0u8; 32]);
    image.extend_from_slice(&valid_until.to_le_bytes());
    image
}
