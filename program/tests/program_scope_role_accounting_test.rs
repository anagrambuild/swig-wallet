//! Regressions for acting-role ProgramScope accounting.
mod common;

use common::*;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    rent::Rent,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        program::Program,
        program_scope::{NumericType, ProgramScope, ProgramScopeType},
    },
    action::{Action, Permission},
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, SwigWithRoles},
    SwigAuthenticateError, Transmutable,
};

const FIXTURE: Pubkey = Pubkey::from_str_const("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");

fn send_with_extra_signers(
    context: &mut Context,
    ix: Instruction,
    authority: &Keypair,
    extra_signers: &[&Keypair],
) -> Result<TransactionMetadata, Box<FailedTransactionMetadata>> {
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let mut signers = vec![&context.default_payer, authority];
    signers.extend_from_slice(extra_signers);
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &signers).unwrap();
    context.svm.send_transaction(tx).map_err(Box::new)
}

fn add_role(
    context: &mut Context,
    swig: &Pubkey,
    root: &Keypair,
    authority: &Keypair,
    actions: Vec<ClientAction>,
) {
    add_authority_with_ed25519_root(
        context,
        swig,
        root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority.pubkey().as_ref(),
        },
        actions,
    )
    .unwrap();
}

fn assert_error(result: Result<TransactionMetadata, Box<FailedTransactionMetadata>>, code: u32) {
    assert_eq!(
        result.unwrap_err().err,
        TransactionError::InstructionError(0, InstructionError::Custom(code))
    );
}

fn scope_spent(state: &SwigWithRoles, role_id: u32) -> u128 {
    let role = state.get_role(role_id).unwrap().unwrap();
    let mut cursor = 0;
    for _ in 0..role.position.num_actions() {
        let header =
            unsafe { Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN]).unwrap() };
        cursor += Action::LEN;
        if header.permission().unwrap() == Permission::ProgramScope {
            // Stored actions are 8-byte aligned; host u128 references require 16.
            return u128::from_le_bytes(role.actions[cursor..cursor + 16].try_into().unwrap());
        }
        cursor += header.length() as usize;
    }
    panic!("missing scope");
}

fn scope(target: Pubkey, start: u64, end: u64) -> ClientAction {
    ClientAction::ProgramScope(ProgramScope {
        current_amount: 0,
        limit: 10,
        window: 0,
        last_reset: 0,
        program_id: FIXTURE.to_bytes(),
        target_account: target.to_bytes(),
        scope_type: ProgramScopeType::Limit as u64,
        numeric_type: NumericType::U64 as u64,
        balance_field_start: start,
        balance_field_end: end,
    })
}

#[test]
fn program_scope_uses_acting_role_before_and_after_cpi() {
    program_scope_role_cases(false);
}

#[test]
fn program_scope_signed_target_uses_acting_role_before_and_after_cpi() {
    program_scope_role_cases(true);
}

fn program_scope_role_cases(target_signs: bool) {
    // Earlier roles can have zero, larger, or unrelated out-of-bounds fields.
    for (earlier_value, earlier_start) in [(0u64, 0), (200, 0), (0, 24)] {
        for after in [0u64, 89, 90, 100, 110] {
            let mut context = setup_test_context().unwrap();
            context
                .svm
                .add_program_from_file(FIXTURE, "../target/deploy/test_program_authority.so")
                .unwrap();
            let root = Keypair::new();
            let earlier = Keypair::new();
            let acting = Keypair::new();
            let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
            let wallet = Pubkey::find_program_address(
                &swig_wallet_address_seeds(swig.as_ref()),
                &program_id(),
            )
            .0;
            let target_keypair = Keypair::new();
            let target = target_keypair.pubkey();
            let extra_signers = if target_signs {
                vec![&target_keypair]
            } else {
                vec![]
            };
            let mut data = vec![0u8; 16];
            data[..8].copy_from_slice(&earlier_value.to_le_bytes());
            data[8..].copy_from_slice(&100u64.to_le_bytes());
            context
                .svm
                .set_account(
                    target,
                    Account {
                        lamports: Rent::default().minimum_balance(16),
                        data,
                        owner: FIXTURE,
                        executable: false,
                        rent_epoch: 0,
                    },
                )
                .unwrap();
            add_role(
                &mut context,
                &swig,
                &root,
                &earlier,
                vec![
                    ClientAction::Program(Program {
                        program_id: FIXTURE.to_bytes(),
                    }),
                    scope(target, earlier_start, earlier_start + 8),
                ],
            );
            add_role(
                &mut context,
                &swig,
                &root,
                &acting,
                vec![
                    ClientAction::Program(Program {
                        program_id: FIXTURE.to_bytes(),
                    }),
                    scope(target, 8, 16),
                ],
            );
            let before = [target, swig].map(|key| context.svm.get_account(&key));
            let mut data = b"writeu64".to_vec();
            data.extend_from_slice(&8u64.to_le_bytes());
            data.extend_from_slice(&after.to_le_bytes());
            let inner = Instruction {
                program_id: FIXTURE,
                accounts: vec![AccountMeta::new(target, target_signs)],
                data,
            };
            let ix =
                SignV2Instruction::new_ed25519(swig, wallet, acting.pubkey(), inner, 2).unwrap();
            let result = send_with_extra_signers(&mut context, ix, &acting, &extra_signers);
            if after < 90 {
                assert_error(
                    result,
                    SwigAuthenticateError::PermissionDeniedInsufficientBalance as u32,
                );
                assert_eq!(
                    [target, swig].map(|key| context.svm.get_account(&key)),
                    before
                );
            } else {
                result.unwrap();
                let account = context.svm.get_account(&swig).unwrap();
                let state = SwigWithRoles::from_bytes(&account.data).unwrap();
                assert_eq!(
                    scope_spent(&state, 2),
                    100u128.saturating_sub(after as u128)
                );
                assert_eq!(scope_spent(&state, 1), 0);
                if after == 90 {
                    let before_retry = [target, swig].map(|key| context.svm.get_account(&key));
                    let mut data = b"writeu64".to_vec();
                    data.extend_from_slice(&8u64.to_le_bytes());
                    data.extend_from_slice(&89u64.to_le_bytes());
                    let inner = Instruction {
                        program_id: FIXTURE,
                        accounts: vec![AccountMeta::new(target, target_signs)],
                        data,
                    };
                    let ix =
                        SignV2Instruction::new_ed25519(swig, wallet, acting.pubkey(), inner, 2)
                            .unwrap();
                    assert_error(
                        send_with_extra_signers(&mut context, ix, &acting, &extra_signers),
                        SwigAuthenticateError::PermissionDeniedInsufficientBalance as u32,
                    );
                    assert_eq!(
                        [target, swig].map(|key| context.svm.get_account(&key)),
                        before_retry
                    );
                }
            }
        }
    }
}
