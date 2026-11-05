#![cfg(not(feature = "program_scope_test"))]
//! Compute cost of the lock-aware admin instructions on a wallet without
//! authorization locks. Uses only builders that also exist on `main`, so the
//! same file can be run there for a like-for-like comparison.

mod common;
use common::*;
use litesvm::types::TransactionMetadata;
use litesvm_token::spl_token;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    instruction::Instruction,
    message::{v0, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, CloseSwigV1Instruction, CloseTokenAccountV1Instruction,
    RemoveAuthorityInstruction, ReplaceAuthorityInstruction, UpdateAuthorityData,
    UpdateAuthorityInstruction,
};
use swig_state::{
    action::sol_limit::SolLimit,
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds},
};

struct Fixture {
    context: SwigTestContext,
    swig: Pubkey,
    wallet: Pubkey,
    root: Keypair,
}

const CARD_ROLE: u32 = 1;

fn fixture() -> Fixture {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    context
        .svm
        .airdrop(&root.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    // A fixed id keeps PDA bump searches, and so compute costs, comparable.
    let id = [7u8; 32];
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let wallet =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id()).0;
    create_swig_ed25519(&mut context, &root, id).unwrap();
    let card = Keypair::new();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: card.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit {
            amount: LAMPORTS_PER_SOL,
        })],
    )
    .unwrap();
    Fixture {
        context,
        swig,
        wallet,
        root,
    }
}

fn send(f: &mut Fixture, ix: Instruction) -> TransactionMetadata {
    f.context.svm.expire_blockhash();
    let ixs = [
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ix,
    ];
    let message = v0::Message::try_compile(
        &f.context.default_payer.pubkey(),
        &ixs,
        &[],
        f.context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&f.context.default_payer, &f.root],
    )
    .unwrap();
    f.context
        .svm
        .send_transaction(tx)
        .unwrap_or_else(|failed| panic!("{:?}\n{}", failed.err, failed.meta.pretty_logs()))
}

/// Returns the compute units of each lock-aware admin instruction, signed by
/// the root, on a wallet without locks.
pub fn admin_instruction_cu() -> Vec<(&'static str, u64)> {
    let mut results = Vec::new();

    let mut f = fixture();
    let payer = f.context.default_payer.pubkey();
    let ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        f.swig,
        payer,
        f.root.pubkey(),
        0,
        CARD_ROLE,
    )
    .unwrap();
    results.push(("RemoveAuthorityV1", send(&mut f, ix).compute_units_consumed));

    let mut f = fixture();
    let payer = f.context.default_payer.pubkey();
    let ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        f.swig,
        payer,
        f.root.pubkey(),
        0,
        CARD_ROLE,
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::SolLimit(SolLimit { amount: 2 })]),
    )
    .unwrap();
    results.push((
        "UpdateAuthorityV1 ReplaceAll",
        send(&mut f, ix).compute_units_consumed,
    ));

    let mut f = fixture();
    let replacement = Keypair::new().pubkey();
    let ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        f.swig,
        f.root.pubkey(),
        0,
        CARD_ROLE,
        replacement.as_ref(),
    )
    .unwrap();
    results.push((
        "ReplaceAuthorityV1",
        send(&mut f, ix).compute_units_consumed,
    ));

    let mut f = fixture();
    let payer = f.context.default_payer.insecure_clone();
    let mint = setup_mint(&mut f.context.svm, &payer).unwrap();
    let wallet = f.wallet;
    let ata = setup_ata(&mut f.context.svm, &mint, &wallet, &payer).unwrap();
    let ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        f.swig,
        f.wallet,
        f.root.pubkey(),
        Keypair::new().pubkey(),
        spl_token::ID,
        vec![ata],
        0,
    )
    .unwrap();
    results.push((
        "CloseTokenAccountV1",
        send(&mut f, ix).compute_units_consumed,
    ));

    let mut f = fixture();
    let ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        f.swig,
        f.wallet,
        f.root.pubkey(),
        Keypair::new().pubkey(),
        0,
    )
    .unwrap();
    results.push(("CloseSwigV1", send(&mut f, ix).compute_units_consumed));

    results
}

#[test]
fn admin_instruction_cu_without_locks() {
    for (name, cu) in admin_instruction_cu() {
        println!("ADMIN_CU {name} {cu}");
    }
}
