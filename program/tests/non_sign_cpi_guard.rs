#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    signature::{Keypair, Signature},
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::error::SwigError;
use swig_interface::{
    AddAuthorityInstruction, AuthorityConfig, ClientAction, CreateInstruction,
    SetRentClaimerV1Instruction, SignV2Instruction, SubAccountSignInstruction,
    SubAccountSignV2Instruction,
};
use swig_state::{
    action::{all::All, all_but_manage_authority::AllButManageAuthority},
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, Swig, SwigWithRoles},
    tail::rent_claimer,
    SwigAuthenticateError,
};

const TEST_PROGRAM_ID: solana_sdk::pubkey::Pubkey =
    solana_sdk::pubkey!("BXAu5ZWHnGun2XZjUZ9nqwiZ5dNVmofPGYdMC4rx4qLV");
const TEST_PROGRAM_PATH: &str = "../target/deploy/test_program_authority.so";
const INVOKE_SWIG_NON_SIGN: [u8; 8] = *b"swigcpi1";
const AUTHORIZED_CPI_SIGNERS: [solana_sdk::pubkey::Pubkey; 2] = [
    solana_sdk::pubkey!("X4o2kSLzqEQjnAzhq3L3BW92aawMV2n2F37EXd2GMpy"),
    solana_sdk::pubkey!("HSrst4iSVPLuKtV8qzmFDLkHTNhKPf5rjg5D8tL6KVCX"),
];

fn deploy_test_program(context: &mut SwigTestContext) {
    let program_data = std::fs::read(TEST_PROGRAM_PATH)
        .expect("build test-program-authority with cargo build-sbf before running this test");
    context
        .svm
        .add_program(TEST_PROGRAM_ID, &program_data)
        .expect("deploy test-program-authority");
}

fn create_instruction(
    payer: solana_sdk::pubkey::Pubkey,
    id: [u8; 32],
) -> (
    Instruction,
    solana_sdk::pubkey::Pubkey,
    solana_sdk::pubkey::Pubkey,
) {
    let (swig, swig_bump) =
        solana_sdk::pubkey::Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (wallet, wallet_bump) = solana_sdk::pubkey::Pubkey::find_program_address(
        &swig_wallet_address_seeds(swig.as_ref()),
        &program_id(),
    );
    let instruction = CreateInstruction::new(
        swig,
        swig_bump,
        payer,
        wallet,
        wallet_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: payer.as_ref(),
        },
        vec![ClientAction::All(All {})],
        id,
    )
    .unwrap();
    (instruction, swig, wallet)
}

fn wrap_non_sign_cpi(inner_instruction: Instruction) -> Instruction {
    let mut accounts = Vec::with_capacity(inner_instruction.accounts.len() + 1);
    accounts.push(AccountMeta::new_readonly(program_id(), false));
    accounts.extend(inner_instruction.accounts);

    let mut data = Vec::with_capacity(INVOKE_SWIG_NON_SIGN.len() + inner_instruction.data.len());
    data.extend_from_slice(&INVOKE_SWIG_NON_SIGN);
    data.extend_from_slice(&inner_instruction.data);

    Instruction {
        program_id: TEST_PROGRAM_ID,
        accounts,
        data,
    }
}

fn send_instruction(
    context: &mut SwigTestContext,
    instruction: Instruction,
) -> Result<(), Box<litesvm::types::FailedTransactionMetadata>> {
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[instruction],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );
    let transaction = VersionedTransaction::try_new(message, &[&context.default_payer]).unwrap();
    context
        .svm
        .send_transaction(transaction)
        .map(|_| ())
        .map_err(Box::new)
}

fn assert_cpi_rejected(result: Result<(), Box<litesvm::types::FailedTransactionMetadata>>) {
    let error = result.expect_err("inbound CPI without an authorized signer must fail");
    assert_eq!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(SwigError::Cpi as u32),)
    );
}

// These fixtures inject signer privileges for the fixed allowlisted addresses.
// The new address is off-curve and needs its deriving program to sign in production.
// Signature verification is disabled here; this does not test that program or its
// PDA seeds, but CPI privilege forwarding and Swig admission remain enforced.
fn setup_test_context_without_signature_verification() -> SwigTestContext {
    let SwigTestContext { svm, default_payer } = setup_test_context().unwrap();
    SwigTestContext {
        svm: svm.with_sigverify(false),
        default_payer,
    }
}

fn send_instruction_without_signature_verification(
    context: &mut SwigTestContext,
    instruction: Instruction,
) -> Result<(), Box<litesvm::types::FailedTransactionMetadata>> {
    assert!(!context.svm.get_sigverify());
    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
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
        .map_err(Box::new)
}

#[test]
fn authorized_cpi_signer_address_types() {
    assert!(AUTHORIZED_CPI_SIGNERS[0].is_on_curve());
    assert!(!AUTHORIZED_CPI_SIGNERS[1].is_on_curve());
}

#[test_log::test]
fn direct_non_sign_instruction_remains_allowed() {
    let mut context = setup_test_context().unwrap();
    let (_, swig, wallet) = create_instruction(context.default_payer.pubkey(), [1u8; 32]);
    let payer = context.default_payer.insecure_clone();

    create_swig_ed25519(&mut context, &payer, [1u8; 32]).unwrap();

    assert!(context.svm.get_account(&swig).is_some());
    assert!(context.svm.get_account(&wallet).is_some());
}

#[test_log::test]
fn unauthorized_signer_cannot_cpi_into_create() {
    let mut context = setup_test_context().unwrap();
    deploy_test_program(&mut context);
    let (inner, swig, wallet) = create_instruction(context.default_payer.pubkey(), [2u8; 32]);
    let outer = wrap_non_sign_cpi(inner);

    assert_cpi_rejected(send_instruction(&mut context, outer));
    assert!(context.svm.get_account(&swig).is_none());
    assert!(context.svm.get_account(&wallet).is_none());
}

#[test_log::test]
fn authorized_key_without_signer_privilege_is_rejected() {
    for signer in AUTHORIZED_CPI_SIGNERS {
        let mut context = setup_test_context().unwrap();
        deploy_test_program(&mut context);
        context
            .svm
            .airdrop(&signer, context.svm.minimum_balance_for_rent_exemption(0))
            .unwrap();
        let (mut inner, swig, wallet) =
            create_instruction(context.default_payer.pubkey(), [3u8; 32]);
        inner
            .accounts
            .push(AccountMeta::new_readonly(signer, false));
        let outer = wrap_non_sign_cpi(inner);

        assert_cpi_rejected(send_instruction(&mut context, outer));
        assert!(context.svm.get_account(&swig).is_none());
        assert!(context.svm.get_account(&wallet).is_none());
    }
}

#[test_log::test]
fn authorized_signer_can_cpi_into_create() {
    for signer in AUTHORIZED_CPI_SIGNERS {
        let mut context = setup_test_context_without_signature_verification();
        deploy_test_program(&mut context);
        context.svm.airdrop(&signer, 10_000_000_000).unwrap();
        let (inner, swig, wallet) = create_instruction(signer, [4u8; 32]);
        let outer = wrap_non_sign_cpi(inner);

        send_instruction_without_signature_verification(&mut context, outer).unwrap();
        assert!(context.svm.get_account(&swig).is_some());
        assert!(context.svm.get_account(&wallet).is_some());
    }
}

#[test_log::test]
fn authorized_signer_can_cpi_into_another_non_sign_instruction() {
    for signer in AUTHORIZED_CPI_SIGNERS {
        let mut context = setup_test_context_without_signature_verification();
        deploy_test_program(&mut context);
        context.svm.airdrop(&signer, 10_000_000_000).unwrap();
        let (create, swig, _) = create_instruction(signer, [5u8; 32]);
        send_instruction_without_signature_verification(&mut context, create).unwrap();
        let claimer = Keypair::new().pubkey();
        let inner = SetRentClaimerV1Instruction::new_with_ed25519_authority(
            swig,
            context.default_payer.pubkey(),
            signer,
            0,
            claimer.to_bytes(),
        )
        .unwrap();
        let outer = wrap_non_sign_cpi(inner);

        send_instruction_without_signature_verification(&mut context, outer).unwrap();

        let account = context.svm.get_account(&swig).unwrap();
        let parts = Swig::split_parts(&account.data).unwrap();
        assert_eq!(
            rent_claimer::read_strict(parts.tail).unwrap(),
            Some(&claimer.to_bytes())
        );
    }
}

#[test_log::test]
fn authorized_signers_can_cpi_into_add_authority() {
    for signer in AUTHORIZED_CPI_SIGNERS {
        let mut context = setup_test_context_without_signature_verification();
        deploy_test_program(&mut context);
        let payer = context.default_payer.insecure_clone();
        let (swig, _) = create_swig_ed25519(&mut context, &payer, [6u8; 32]).unwrap();
        context.svm.airdrop(&signer, 1_000_000).unwrap();
        let new_authority = Keypair::new().pubkey();
        let mut inner = AddAuthorityInstruction::new_with_ed25519_authority(
            swig,
            payer.pubkey(),
            payer.pubkey(),
            0,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: new_authority.as_ref(),
            },
            vec![ClientAction::All(All {})],
        )
        .unwrap();
        // CPI admission signer is separate from the wallet's acting authority.
        inner.accounts.push(AccountMeta::new_readonly(signer, true));
        send_instruction_without_signature_verification(&mut context, wrap_non_sign_cpi(inner))
            .unwrap();
        let account = context.svm.get_account(&swig).unwrap();
        let swig = SwigWithRoles::from_bytes(&account.data).unwrap();
        assert_eq!(swig.state.roles, 2);
        assert!(swig
            .get_role(1)
            .unwrap()
            .unwrap()
            .authority
            .match_data(new_authority.as_ref()));
    }
}

#[test_log::test]
fn add_authority_rejects_allowlisted_keys_without_signer_privilege() {
    for signer in AUTHORIZED_CPI_SIGNERS {
        let mut context = setup_test_context().unwrap();
        deploy_test_program(&mut context);
        let payer = context.default_payer.insecure_clone();
        let (swig, _) = create_swig_ed25519(&mut context, &payer, [7u8; 32]).unwrap();
        context.svm.airdrop(&signer, 1_000_000).unwrap();
        let before = context.svm.get_account(&swig).unwrap();
        let payer_before = context.svm.get_account(&payer.pubkey()).unwrap();
        let new_authority = Keypair::new().pubkey();
        let mut inner = AddAuthorityInstruction::new_with_ed25519_authority(
            swig,
            payer.pubkey(),
            payer.pubkey(),
            0,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: new_authority.as_ref(),
            },
            vec![ClientAction::All(All {})],
        )
        .unwrap();
        inner
            .accounts
            .push(AccountMeta::new_readonly(signer, false));
        assert_cpi_rejected(send_instruction(&mut context, wrap_non_sign_cpi(inner)));
        assert_eq!(context.svm.get_account(&swig).unwrap(), before);
        // Only the transaction fee is charged; no rent top-up occurs.
        assert_eq!(
            context.svm.get_account(&payer.pubkey()).unwrap().lamports,
            payer_before.lamports - 5_000
        );
    }
}

#[test_log::test]
fn authorized_cpi_signers_still_need_wallet_management_permission() {
    for signer in AUTHORIZED_CPI_SIGNERS {
        let mut context = setup_test_context_without_signature_verification();
        deploy_test_program(&mut context);
        let payer = context.default_payer.insecure_clone();
        let root = Keypair::new();
        context.svm.airdrop(&root.pubkey(), 1_000_000_000).unwrap();
        let (swig, _) = create_swig_ed25519(&mut context, &root, [8u8; 32]).unwrap();
        context.svm.airdrop(&signer, 1_000_000).unwrap();
        add_authority_with_ed25519_root(
            &mut context,
            &swig,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: signer.as_ref(),
            },
            vec![ClientAction::AllButManageAuthority(
                AllButManageAuthority {},
            )],
        )
        .unwrap();
        let before = context.svm.get_account(&swig).unwrap();
        let new_authority = Keypair::new().pubkey();
        let inner = AddAuthorityInstruction::new_with_ed25519_authority(
            swig,
            payer.pubkey(),
            signer,
            1,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: new_authority.as_ref(),
            },
            vec![ClientAction::All(All {})],
        )
        .unwrap();
        let error =
            send_instruction_without_signature_verification(&mut context, wrap_non_sign_cpi(inner))
                .unwrap_err();
        assert_eq!(
            error.err,
            TransactionError::InstructionError(
                0,
                InstructionError::Custom(
                    SwigAuthenticateError::PermissionDeniedToManageAuthority as u32
                )
            )
        );
        assert_eq!(context.svm.get_account(&swig).unwrap(), before);
    }
}

#[test_log::test]
fn authorized_cpi_signers_cannot_impersonate_wallet_authority() {
    for signer in AUTHORIZED_CPI_SIGNERS {
        let mut context = setup_test_context_without_signature_verification();
        deploy_test_program(&mut context);
        let payer = context.default_payer.insecure_clone();
        let (swig, _) = create_swig_ed25519(&mut context, &payer, [9u8; 32]).unwrap();
        context.svm.airdrop(&signer, 1_000_000).unwrap();
        let before = context.svm.get_account(&swig).unwrap();
        let new_authority = Keypair::new().pubkey();
        let inner = AddAuthorityInstruction::new_with_ed25519_authority(
            swig,
            payer.pubkey(),
            signer,
            0,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: new_authority.as_ref(),
            },
            vec![ClientAction::All(All {})],
        )
        .unwrap();
        let error =
            send_instruction_without_signature_verification(&mut context, wrap_non_sign_cpi(inner))
                .unwrap_err();
        assert_eq!(
            error.err,
            TransactionError::InstructionError(
                0,
                InstructionError::Custom(SwigAuthenticateError::PermissionDenied as u32)
            )
        );
        assert_eq!(context.svm.get_account(&swig).unwrap(), before);
    }
}

#[test_log::test]
fn authorized_signers_cannot_cpi_into_sign_instructions() {
    for signer in AUTHORIZED_CPI_SIGNERS {
        let mut context = setup_test_context_without_signature_verification();
        deploy_test_program(&mut context);
        let payer = context.default_payer.insecure_clone();
        let (swig, _) = create_swig_ed25519(&mut context, &payer, [10u8; 32]).unwrap();
        context.svm.airdrop(&signer, 1_000_000).unwrap();
        let (wallet, _) = solana_sdk::pubkey::Pubkey::find_program_address(
            &swig_wallet_address_seeds(swig.as_ref()),
            &program_id(),
        );
        let before = context.svm.get_account(&swig).unwrap();
        let wallet_before = context.svm.get_account(&wallet).unwrap();
        let transfer = solana_system_interface::instruction::transfer(&wallet, &payer.pubkey(), 1);
        // Production builders supply the complete wire format. Placeholder subaccount
        // accounts are intentional: the dispatcher must reject before any handler runs.
        let instructions = [
            SignV2Instruction::new_ed25519(swig, wallet, signer, transfer, 0).unwrap(),
            SubAccountSignInstruction::new_with_ed25519_authority(swig, wallet, signer, 0, vec![])
                .unwrap(),
            SubAccountSignV2Instruction::new_with_ed25519_authority(
                swig,
                swig,
                wallet,
                signer,
                0,
                0,
                vec![],
            )
            .unwrap(),
        ];
        for inner in instructions {
            assert_cpi_rejected(send_instruction_without_signature_verification(
                &mut context,
                wrap_non_sign_cpi(inner),
            ));
            assert_eq!(context.svm.get_account(&swig).unwrap(), before);
            assert_eq!(context.svm.get_account(&wallet).unwrap(), wallet_before);
        }
    }
}
