#![cfg(not(feature = "program_scope_test"))]
#![allow(deprecated)] // Pinocchio/Shank still returns NotEnoughAccountKeys.
mod common;
#[path = "../src/error.rs"]
mod swig_error;

use common::*;
use litesvm::types::TransactionMetadata;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    instruction::{Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_error::SwigError;
use swig_interface::{
    reservation::{ReservationAddressOptions, ReservationV1},
    AuthorityConfig, ClientAction, CloseSwigV1Instruction, CreateInstruction, SignV2Instruction,
};
use swig_state::{
    action::all::All,
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

fn send(
    context: &mut SwigTestContext,
    instructions: &[Instruction],
    signers: &[&Keypair],
) -> Result<TransactionMetadata, TransactionError> {
    context.svm.expire_blockhash();
    let mut ixs = vec![ComputeBudgetInstruction::set_compute_unit_limit(600_000)];
    ixs.extend_from_slice(instructions);
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &ixs,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let mut keys = vec![&context.default_payer];
    keys.extend_from_slice(signers);
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &keys).unwrap();
    context.svm.send_transaction(tx).map_err(|error| {
        eprintln!("{}", error.meta.pretty_logs());
        error.err
    })
}

fn ed_reservation(owner: &Keypair) -> ReservationV1 {
    ReservationV1::new(
        program_id(),
        AuthorityType::Ed25519,
        owner.pubkey().as_ref(),
        ReservationAddressOptions::default(),
    )
    .unwrap()
}

#[test]
fn reservation_activates_all_direct_owners_without_owner_signature() {
    let ed = Keypair::new_from_array([3; 32]);
    let mut owners = vec![(AuthorityType::Ed25519, ed.pubkey().to_bytes().to_vec())];
    for (kind, curve) in [
        (AuthorityType::Secp256k1, Nid::SECP256K1),
        (AuthorityType::Secp256r1, Nid::X9_62_PRIME256V1),
    ] {
        let group = EcGroup::from_curve_name(curve).unwrap();
        let key = EcKey::generate(&group).unwrap();
        owners.push((
            kind,
            key.public_key()
                .to_bytes(
                    &group,
                    PointConversionForm::COMPRESSED,
                    &mut BigNumContext::new().unwrap(),
                )
                .unwrap(),
        ));
    }
    for (kind, key) in owners {
        let mut context = setup_test_context().unwrap();
        let reservation = ReservationV1::new(
            program_id(),
            kind,
            &key,
            ReservationAddressOptions::default(),
        )
        .unwrap();
        let addresses = reservation.addresses().unwrap();
        let instruction = reservation
            .create_instruction(context.default_payer.pubkey())
            .unwrap();
        assert_eq!(instruction.data[..2], 24u16.to_le_bytes());
        assert_eq!(instruction.data[2..], reservation.package_bytes);
        assert_eq!(
            instruction
                .accounts
                .iter()
                .filter(|meta| meta.is_signer)
                .count(),
            1
        );
        let receipt = send(&mut context, std::slice::from_ref(&instruction), &[]).unwrap();
        println!(
            "reservation {kind:?} activation CU: {}",
            receipt.compute_units_consumed
        );
        assert!(receipt.compute_units_consumed < 600_000);
        let account = context.svm.get_account(&addresses.swig_address).unwrap();
        let wallet = context.svm.get_account(&addresses.wallet_address).unwrap();
        assert_eq!(account.owner, program_id());
        assert_eq!(wallet.owner, solana_system_interface::program::ID);
        assert!(wallet.data.is_empty());
        let stored = SwigWithRoles::from_bytes(&account.data).unwrap();
        assert_eq!(stored.state.id, addresses.commitment);
        assert_eq!(stored.state.roles, 1);
        assert_eq!(stored.state.role_counter, 1);
        assert_eq!(stored.state.sub_account_counter, 0);
        let role = stored.get_role(0).unwrap().unwrap();
        assert_eq!(role.authority.authority_type(), kind);
        assert_eq!(role.authority.identity().unwrap(), key);
        assert!(role.get_action::<All>(&[]).unwrap().is_some());
        assert_eq!(
            role.authority.signature_odometer(),
            if kind == AuthorityType::Ed25519 {
                None
            } else {
                Some(0)
            }
        );
        send(&mut context, &[instruction], &[]).unwrap();
        assert_eq!(
            context.svm.get_account(&addresses.swig_address).unwrap(),
            account
        );
        assert_eq!(
            context.svm.get_account(&addresses.wallet_address).unwrap(),
            wallet
        );
    }
}

#[test]
fn reservation_preserves_prefunding_and_only_charges_rent_shortfall() {
    for case in 0..3 {
        let mut context = setup_test_context().unwrap();
        let funding = match case {
            0 => 0,
            1 => context.svm.minimum_balance_for_rent_exemption(0),
            _ => 1_000_000_000,
        };
        let reservation = ed_reservation(&Keypair::new());
        let addresses = reservation.addresses().unwrap();
        let payer = Keypair::new();
        context.svm.airdrop(&payer.pubkey(), 2_000_000_000).unwrap();
        if funding > 0 {
            context
                .svm
                .airdrop(&addresses.swig_address, funding)
                .unwrap();
            context
                .svm
                .airdrop(&addresses.wallet_address, funding)
                .unwrap();
        }
        let ix = reservation.create_instruction(payer.pubkey()).unwrap();
        let before = context.svm.get_account(&payer.pubkey()).unwrap().lamports;
        send(&mut context, &[ix], &[&payer]).unwrap();
        let config = context.svm.get_account(&addresses.swig_address).unwrap();
        let wallet = context.svm.get_account(&addresses.wallet_address).unwrap();
        let config_rent = context
            .svm
            .minimum_balance_for_rent_exemption(config.data.len());
        let wallet_rent = context.svm.minimum_balance_for_rent_exemption(0);
        assert_eq!(config.lamports, funding.max(config_rent));
        assert_eq!(wallet.lamports, funding.max(wallet_rent));
        assert_eq!(
            before - context.svm.get_account(&payer.pubkey()).unwrap().lamports,
            config_rent.saturating_sub(funding) + wallet_rent.saturating_sub(funding)
        );
    }
}

#[test]
fn reservation_retry_preserves_rotated_owner_and_rent_claimer_then_close_is_permanent() {
    let mut context = setup_test_context().unwrap();
    let original = Keypair::new();
    let replacement = Keypair::new();
    let reservation = ed_reservation(&original);
    let addresses = reservation.addresses().unwrap();
    let create = reservation
        .create_instruction(context.default_payer.pubkey())
        .unwrap();
    send(&mut context, std::slice::from_ref(&create), &[]).unwrap();
    let replace = swig_interface::ReplaceAuthorityInstruction::new_with_ed25519_authority(
        addresses.swig_address,
        original.pubkey(),
        0,
        0,
        replacement.pubkey().as_ref(),
    )
    .unwrap();
    send(&mut context, &[replace], &[&original]).unwrap();
    let claimer = Pubkey::new_unique();
    context.svm.airdrop(&claimer, 1_000_000).unwrap();
    set_rent_claimer_with_ed25519(
        &mut context,
        &addresses.swig_address,
        &replacement,
        0,
        claimer,
    )
    .unwrap();
    let before = context.svm.get_account(&addresses.swig_address).unwrap();
    send(&mut context, std::slice::from_ref(&create), &[]).unwrap();
    assert_eq!(
        context.svm.get_account(&addresses.swig_address).unwrap(),
        before
    );
    let stored = SwigWithRoles::from_bytes(&before.data).unwrap();
    assert_eq!(
        stored
            .get_role(0)
            .unwrap()
            .unwrap()
            .authority
            .identity()
            .unwrap(),
        replacement.pubkey().as_ref()
    );

    let close = CloseSwigV1Instruction::new_with_ed25519_authority(
        addresses.swig_address,
        addresses.wallet_address,
        replacement.pubkey(),
        claimer,
        0,
    )
    .unwrap();
    let claimer_before = context.svm.get_account(&claimer).unwrap().lamports;
    let wallet_before = context
        .svm
        .get_account(&addresses.wallet_address)
        .unwrap()
        .lamports;
    send(&mut context, &[close], &[&replacement]).unwrap();
    let tombstone = context.svm.get_account(&addresses.swig_address).unwrap();
    assert_eq!(tombstone.owner, program_id());
    assert_eq!(tombstone.data, vec![255]);
    assert_eq!(
        context.svm.get_account(&claimer).unwrap().lamports - claimer_before,
        before.lamports + wallet_before - tombstone.lamports
    );
    context
        .svm
        .airdrop(&addresses.swig_address, 5_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&addresses.wallet_address, 5_000_000)
        .unwrap();
    let closed = context.svm.get_account(&addresses.swig_address).unwrap();
    let wallet = context.svm.get_account(&addresses.wallet_address).unwrap();
    assert_eq!(
        send(&mut context, &[create], &[]).unwrap_err(),
        TransactionError::InstructionError(
            1,
            InstructionError::Custom(SwigError::InvalidSwigAccountDiscriminator as u32)
        )
    );
    assert_eq!(
        context.svm.get_account(&addresses.swig_address).unwrap(),
        closed
    );
    assert_eq!(
        context.svm.get_account(&addresses.wallet_address).unwrap(),
        wallet
    );
}

#[test]
fn reservation_signs_with_ed25519_and_both_secp_curves_and_retry_preserves_odometer() {
    use alloy_primitives::B256;
    use alloy_signer::SignerSync;
    use alloy_signer_local::LocalSigner;
    use solana_sdk::clock::Clock;
    let ed = Keypair::new();
    let k1 = LocalSigner::random();
    let k1_key = k1.credential().verifying_key().to_encoded_point(true);
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let r1 = EcKey::generate(&group).unwrap();
    let r1_key: [u8; 33] = r1
        .public_key()
        .to_bytes(
            &group,
            PointConversionForm::COMPRESSED,
            &mut BigNumContext::new().unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
    for (kind, key) in [
        (AuthorityType::Ed25519, ed.pubkey().to_bytes().to_vec()),
        (AuthorityType::Secp256k1, k1_key.as_bytes().to_vec()),
        (AuthorityType::Secp256r1, r1_key.to_vec()),
    ] {
        let mut context = setup_test_context().unwrap();
        let reservation = ReservationV1::new(
            program_id(),
            kind,
            &key,
            ReservationAddressOptions::default(),
        )
        .unwrap();
        let a = reservation.addresses().unwrap();
        let create = reservation
            .create_instruction(context.default_payer.pubkey())
            .unwrap();
        send(&mut context, std::slice::from_ref(&create), &[]).unwrap();
        context.svm.airdrop(&a.wallet_address, 10_000_000).unwrap();
        let recipient = Pubkey::new_unique();
        context.svm.airdrop(&recipient, 1_000_000).unwrap();
        let transfer = solana_system_interface::instruction::transfer(
            &a.wallet_address,
            &recipient,
            1_000_000,
        );
        let slot = context.svm.get_sysvar::<Clock>().slot;
        let ixs = match kind {
            AuthorityType::Ed25519 => vec![SignV2Instruction::new_ed25519(
                a.swig_address,
                a.wallet_address,
                ed.pubkey(),
                transfer,
                0,
            )
            .unwrap()],
            AuthorityType::Secp256k1 => vec![SignV2Instruction::new_secp256k1_with_signers(
                a.swig_address,
                a.wallet_address,
                |hash: &[u8]| {
                    k1.sign_hash_sync(&B256::from_slice(hash))
                        .unwrap()
                        .as_bytes()
                },
                slot,
                1,
                transfer,
                0,
                &[context.default_payer.pubkey()],
            )
            .unwrap()],
            AuthorityType::Secp256r1 => SignV2Instruction::new_secp256r1_with_signers(
                a.swig_address,
                a.wallet_address,
                |hash: &[u8]| {
                    solana_secp256r1_program::sign_message(hash, &r1.private_key_to_der().unwrap())
                        .unwrap()
                },
                slot,
                1,
                transfer,
                0,
                &r1_key,
                &[context.default_payer.pubkey()],
            )
            .unwrap(),
            _ => unreachable!(),
        };
        let signers = if kind == AuthorityType::Ed25519 {
            vec![&ed]
        } else {
            vec![]
        };
        send(&mut context, &ixs, &signers).unwrap();
        assert_eq!(
            context.svm.get_account(&recipient).unwrap().lamports,
            2_000_000
        );
        let before = context.svm.get_account(&a.swig_address).unwrap();
        let wallet_before = context.svm.get_account(&a.wallet_address).unwrap();
        send(&mut context, &[create], &[]).unwrap();
        assert_eq!(context.svm.get_account(&a.swig_address).unwrap(), before);
        assert_eq!(
            context.svm.get_account(&a.wallet_address).unwrap(),
            wallet_before
        );
        if kind != AuthorityType::Ed25519 {
            assert_eq!(
                SwigWithRoles::from_bytes(&before.data)
                    .unwrap()
                    .get_role(0)
                    .unwrap()
                    .unwrap()
                    .authority
                    .signature_odometer(),
                Some(1)
            );
            let expected = match kind {
                AuthorityType::Secp256k1 => {
                    swig_state::SwigAuthenticateError::PermissionDeniedSecp256k1SignatureReused
                },
                _ => swig_state::SwigAuthenticateError::PermissionDeniedSecp256r1SignatureReused,
            };
            let instruction_index = if kind == AuthorityType::Secp256r1 {
                2
            } else {
                1
            };
            assert_eq!(
                send(&mut context, &ixs, &[]).unwrap_err(),
                TransactionError::InstructionError(
                    instruction_index,
                    InstructionError::Custom(expected as u32)
                )
            );
            assert_eq!(context.svm.get_account(&a.swig_address).unwrap(), before);
            assert_eq!(
                context.svm.get_account(&a.wallet_address).unwrap(),
                wallet_before
            );
        }
    }
}

#[test]
fn reservation_rejects_invalid_account_contracts_without_changing_prefunded_accounts() {
    for case in 0..18 {
        let mut context = setup_test_context().unwrap();
        let reservation = ed_reservation(&Keypair::new());
        let a = reservation.addresses().unwrap();
        let payer = Keypair::new();
        context.svm.airdrop(&payer.pubkey(), 2_000_000_000).unwrap();
        context.svm.airdrop(&a.swig_address, 1_000_000_000).unwrap();
        context
            .svm
            .airdrop(&a.wallet_address, 1_000_000_000)
            .unwrap();
        let mut ix = reservation.create_instruction(payer.pubkey()).unwrap();
        let mut signers = vec![&payer];
        let expected = match case {
            0 => {
                ix.accounts[1].is_signer = false;
                signers.clear();
                InstructionError::Custom(SwigError::PayerMustBeWritableSigner as u32)
            },
            1 => {
                ix.accounts[1].is_writable = false;
                InstructionError::Custom(SwigError::PayerMustBeWritableSigner as u32)
            },
            2 | 3 => {
                ix.accounts[if case == 2 { 0 } else { 2 }].is_writable = false;
                InstructionError::InvalidAccountData
            },
            4 => {
                ix.accounts[3].pubkey = Pubkey::new_unique();
                InstructionError::Custom(SwigError::InvalidSystemProgram as u32)
            },
            5 | 6 => {
                ix.accounts[if case == 5 { 0 } else { 2 }].pubkey = Pubkey::new_unique();
                InstructionError::Custom(SwigError::InvalidSeedSwigAccount as u32)
            },
            7 => {
                ix.accounts.swap(0, 2);
                InstructionError::Custom(SwigError::InvalidSeedSwigAccount as u32)
            },
            8 => {
                ix.accounts[2].pubkey = a.swig_address;
                InstructionError::InvalidArgument
            },
            9 => {
                ix.accounts[0].pubkey = payer.pubkey();
                InstructionError::InvalidArgument
            },
            10 => {
                ix.accounts[2].pubkey = payer.pubkey();
                InstructionError::InvalidArgument
            },
            11..=14 => {
                let key = if case <= 12 {
                    a.swig_address
                } else {
                    a.wallet_address
                };
                let mut account = context.svm.get_account(&key).unwrap();
                if case % 2 == 1 {
                    account.owner = Pubkey::new_unique();
                } else {
                    account.data = vec![1; 8];
                }
                context.svm.set_account(key, account).unwrap();
                InstructionError::Custom(if case % 2 == 1 {
                    SwigError::OwnerMismatchSwigAccount
                } else {
                    SwigError::AccountNotEmptySwigAccount
                } as u32)
            },
            15 | 16 => {
                let mut account = context.svm.get_account(&payer.pubkey()).unwrap();
                if case == 15 {
                    account.owner = Pubkey::new_unique();
                } else {
                    account.data = vec![1; 8];
                }
                context.svm.set_account(payer.pubkey(), account).unwrap();
                if case == 15 {
                    InstructionError::IllegalOwner
                } else {
                    InstructionError::InvalidAccountData
                }
            },
            17 => {
                ix.accounts.truncate(3);
                InstructionError::NotEnoughAccountKeys
            },
            _ => unreachable!(),
        };
        let before: Vec<_> = [a.swig_address, a.wallet_address, payer.pubkey()]
            .into_iter()
            .map(|key| (key, context.svm.get_account(&key)))
            .collect();
        assert_eq!(
            send(&mut context, &[ix], &signers).unwrap_err(),
            TransactionError::InstructionError(1, expected),
            "case {case}"
        );
        for (key, account) in before {
            assert_eq!(context.svm.get_account(&key), account, "case {case}");
        }
    }
}

#[test]
fn reservation_rejects_malformed_packages_before_account_creation() {
    let owner = Keypair::new();
    let mut context = setup_test_context().unwrap();
    let reservation = ed_reservation(&owner);
    let a = reservation.addresses().unwrap();
    let base = reservation
        .create_instruction(context.default_payer.pubkey())
        .unwrap();
    let mut cases = Vec::new();
    for len in 2..base.data.len() {
        cases.push((
            base.data[..len].to_vec(),
            InstructionError::InvalidInstructionData,
        ));
    }
    let mut trailing = base.data.clone();
    trailing.push(0);
    cases.push((trailing, InstructionError::InvalidInstructionData));
    for (offset, value, error) in [
        (2, 2, InstructionError::InvalidInstructionData),
        (67, 2, InstructionError::InvalidInstructionData),
        (68, 1, InstructionError::InvalidInstructionData),
        (3, base.data[3] ^ 1, InstructionError::IncorrectProgramId),
        (
            35,
            base.data[35] ^ 1,
            InstructionError::Custom(SwigError::InvalidSeedSwigAccount as u32),
        ),
    ] {
        let mut bytes = base.data.clone();
        bytes[offset] = value;
        cases.push((bytes, error));
    }
    for key in [[0u8; 32], [0xff; 32], {
        let mut key = [0; 32];
        key[0] = 1;
        key
    }] {
        let mut bytes = base.data.clone();
        bytes[69..].copy_from_slice(&key);
        cases.push((bytes, InstructionError::InvalidInstructionData));
    }
    for (data, expected) in cases {
        let mut ix = base.clone();
        ix.data = data;
        assert_eq!(
            send(&mut context, &[ix], &[]).unwrap_err(),
            TransactionError::InstructionError(1, expected)
        );
        assert!(context.svm.get_account(&a.swig_address).is_none());
        assert!(context.svm.get_account(&a.wallet_address).is_none());
    }
}

#[test]
fn reservation_rejects_off_curve_secp_keys_on_chain() {
    let mut context = setup_test_context().unwrap();
    for (kind, nid) in [
        (AuthorityType::Secp256k1, Nid::SECP256K1),
        (AuthorityType::Secp256r1, Nid::X9_62_PRIME256V1),
    ] {
        let group = EcGroup::from_curve_name(nid).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let public = key
            .public_key()
            .to_bytes(
                &group,
                PointConversionForm::COMPRESSED,
                &mut BigNumContext::new().unwrap(),
            )
            .unwrap();
        let reservation = ReservationV1::new(
            program_id(),
            kind,
            &public,
            ReservationAddressOptions::default(),
        )
        .unwrap();
        let a = reservation.addresses().unwrap();
        let base = reservation
            .create_instruction(context.default_payer.pubkey())
            .unwrap();
        for malformed in [
            vec![0; 33],
            {
                let mut key = vec![0xff; 33];
                key[0] = 2;
                key
            },
            {
                let mut key = vec![0; 33];
                key[0] = 2;
                key[32] = if kind == AuthorityType::Secp256k1 {
                    0
                } else {
                    1
                };
                key
            },
        ] {
            // These in-field x coordinates have no point on the selected curve.
            let mut ix = base.clone();
            ix.data[69..].copy_from_slice(&malformed);
            assert_eq!(
                send(&mut context, &[ix], &[]).unwrap_err(),
                TransactionError::InstructionError(1, InstructionError::InvalidInstructionData)
            );
            assert!(context.svm.get_account(&a.swig_address).is_none());
            assert!(context.svm.get_account(&a.wallet_address).is_none());
        }
    }
}

#[test]
fn reservation_and_legacy_create_cannot_initialize_each_others_namespaces() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let reservation = ed_reservation(&root);
    let a = reservation.addresses().unwrap();
    let create = reservation
        .create_instruction(context.default_payer.pubkey())
        .unwrap();
    let (legacy, bump) =
        Pubkey::find_program_address(&swig_account_seeds(&a.commitment), &program_id());
    let (legacy_wallet, wallet_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(legacy.as_ref()), &program_id());
    let legacy_create = CreateInstruction::new(
        legacy,
        bump,
        context.default_payer.pubkey(),
        legacy_wallet,
        wallet_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: root.pubkey().as_ref(),
        },
        vec![ClientAction::All(All)],
        a.commitment,
    )
    .unwrap();
    let mut wrong_legacy = legacy_create.clone();
    wrong_legacy.accounts[0].pubkey = a.swig_address;
    wrong_legacy.accounts[2].pubkey = a.wallet_address;
    let mut wrong_reserved = create.clone();
    wrong_reserved.accounts[0].pubkey = legacy;
    wrong_reserved.accounts[2].pubkey = legacy_wallet;
    for ix in [wrong_legacy, wrong_reserved] {
        assert_eq!(
            send(&mut context, &[ix], &[]).unwrap_err(),
            TransactionError::InstructionError(
                1,
                InstructionError::Custom(SwigError::InvalidSeedSwigAccount as u32)
            )
        );
        for key in [legacy, legacy_wallet, a.swig_address, a.wallet_address] {
            assert!(context.svm.get_account(&key).is_none());
        }
    }
    send(&mut context, &[legacy_create], &[]).unwrap();
    send(&mut context, &[create], &[]).unwrap();
    assert_ne!(a.swig_address, legacy);
    assert_ne!(a.wallet_address, legacy_wallet);
}

#[test]
fn reservation_retry_rejects_corrupt_immutable_state_and_malformed_tails() {
    for offset in [1, 2, 40, 41, 0, usize::MAX] {
        let mut context = setup_test_context().unwrap();
        let reservation = ed_reservation(&Keypair::new());
        let a = reservation.addresses().unwrap();
        let create = reservation
            .create_instruction(context.default_payer.pubkey())
            .unwrap();
        send(&mut context, std::slice::from_ref(&create), &[]).unwrap();
        let mut corrupted = context.svm.get_account(&a.swig_address).unwrap();
        if offset == usize::MAX {
            corrupted.data.extend_from_slice(&[0; 8]);
        } else {
            corrupted.data[offset] ^= 1;
        }
        context
            .svm
            .set_account(a.swig_address, corrupted.clone())
            .unwrap();
        let expected = if offset == 0 {
            InstructionError::Custom(SwigError::InvalidSwigAccountDiscriminator as u32)
        } else if offset == usize::MAX {
            InstructionError::Custom(swig_state::SwigStateError::InvalidRentClaimerLayout as u32)
        } else {
            InstructionError::InvalidAccountData
        };
        assert_eq!(
            send(&mut context, &[create], &[]).unwrap_err(),
            TransactionError::InstructionError(1, expected)
        );
        assert_eq!(context.svm.get_account(&a.swig_address).unwrap(), corrupted);
    }
}

#[test]
fn reservation_insufficient_payer_funds_does_not_allocate_or_top_up() {
    let mut context = setup_test_context().unwrap();
    let payer = Keypair::new();
    context.svm.airdrop(&payer.pubkey(), 1_000_000).unwrap();
    let reservation = ed_reservation(&Keypair::new());
    let a = reservation.addresses().unwrap();
    let create = reservation.create_instruction(payer.pubkey()).unwrap();
    let before = context.svm.get_account(&payer.pubkey()).unwrap();
    assert_eq!(
        send(&mut context, &[create], &[&payer]).unwrap_err(),
        TransactionError::InstructionError(1, InstructionError::InsufficientFunds)
    );
    assert_eq!(context.svm.get_account(&payer.pubkey()).unwrap(), before);
    assert!(context.svm.get_account(&a.swig_address).is_none());
    assert!(context.svm.get_account(&a.wallet_address).is_none());
}

#[test]
fn reservation_uses_v2_subaccounts_and_cannot_access_legacy_v1_children() {
    use swig_interface::{
        CloseSubAccountV2Instruction, CreateSubAccountInstruction, CreateSubAccountV2Instruction,
        SubAccountSignV2Instruction, ToggleSubAccountV2Instruction,
        WithdrawFromSubAccountV2Instruction,
    };
    use swig_state::swig::{
        sub_account_seeds, sub_account_v2_asset_seeds, sub_account_v2_state_seeds,
    };
    let mut context = setup_test_context().unwrap();
    let owner = Keypair::new();
    let reservation = ed_reservation(&owner);
    let a = reservation.addresses().unwrap();
    let payer = context.default_payer.pubkey();
    let activate = reservation.create_instruction(payer).unwrap();
    send(&mut context, std::slice::from_ref(&activate), &[]).unwrap();
    let state = Pubkey::find_program_address(
        &sub_account_v2_state_seeds(a.swig_address.as_ref(), &0u32.to_le_bytes()),
        &program_id(),
    )
    .0;
    let asset = Pubkey::find_program_address(
        &sub_account_v2_asset_seeds(a.swig_address.as_ref(), &0u32.to_le_bytes()),
        &program_id(),
    )
    .0;
    let create = CreateSubAccountV2Instruction::new_with_ed25519_authority(
        a.swig_address,
        owner.pubkey(),
        payer,
        state,
        asset,
        0,
    )
    .unwrap();
    assert_eq!(
        send(&mut context, std::slice::from_ref(&create), &[&owner]).unwrap_err(),
        TransactionError::InstructionError(
            1,
            InstructionError::Custom(SwigError::AuthorityCannotCreateSubAccountV2 as u32)
        )
    );
    let grant = swig_interface::UpdateAuthorityInstruction::new_with_ed25519_authority(
        a.swig_address,
        payer,
        owner.pubkey(),
        0,
        0,
        swig_interface::UpdateAuthorityData::AddActions(vec![ClientAction::SubAccountV2Create(
            swig_state::action::sub_account_v2::SubAccountV2Create,
        )]),
    )
    .unwrap();
    send(&mut context, &[grant], &[&owner]).unwrap();
    send(&mut context, &[create], &[&owner]).unwrap();
    context.svm.airdrop(&asset, 5_000_000).unwrap();
    let recipient = Pubkey::new_unique();
    context.svm.airdrop(&recipient, 1_000_000).unwrap();
    let transfer = solana_system_interface::instruction::transfer(&asset, &recipient, 1_000_000);
    let sign = SubAccountSignV2Instruction::new_with_ed25519_authority(
        a.swig_address,
        state,
        asset,
        owner.pubkey(),
        0,
        0,
        vec![transfer],
    )
    .unwrap();
    send(&mut context, &[sign], &[&owner]).unwrap();
    assert_eq!(
        context.svm.get_account(&recipient).unwrap().lamports,
        2_000_000
    );
    let withdraw = WithdrawFromSubAccountV2Instruction::new_with_ed25519_authority(
        a.swig_address,
        owner.pubkey(),
        payer,
        state,
        asset,
        a.wallet_address,
        0,
        0,
        1_000_000,
    )
    .unwrap();
    let wallet_before = context.svm.get_account(&a.wallet_address).unwrap().lamports;
    send(&mut context, &[withdraw], &[&owner]).unwrap();
    assert_eq!(
        context.svm.get_account(&a.wallet_address).unwrap().lamports,
        wallet_before + 1_000_000
    );
    let before = context.svm.get_account(&a.swig_address).unwrap();
    send(&mut context, &[activate], &[]).unwrap();
    assert_eq!(context.svm.get_account(&a.swig_address).unwrap(), before);
    assert_eq!(
        SwigWithRoles::from_bytes(&before.data)
            .unwrap()
            .state
            .sub_account_counter,
        1
    );
    let toggle = ToggleSubAccountV2Instruction::new_with_ed25519_authority(
        a.swig_address,
        owner.pubkey(),
        payer,
        state,
        0,
        0,
        false,
    )
    .unwrap();
    send(&mut context, &[toggle], &[&owner]).unwrap();
    let close = CloseSubAccountV2Instruction::new_with_ed25519_authority(
        a.swig_address,
        payer,
        state,
        asset,
        a.wallet_address,
        None,
        owner.pubkey(),
        0,
        0,
    )
    .unwrap();
    send(&mut context, &[close], &[&owner]).unwrap();
    assert!(context.svm.get_account(&state).is_none());
    assert!(context.svm.get_account(&asset).is_none());
    let (legacy_child, legacy_bump) = Pubkey::find_program_address(
        &sub_account_seeds(&a.commitment, &0u32.to_le_bytes()),
        &program_id(),
    );
    let legacy = CreateSubAccountInstruction::new_with_ed25519_authority(
        a.swig_address,
        owner.pubkey(),
        payer,
        legacy_child,
        0,
        legacy_bump,
    )
    .unwrap();
    let before = context.svm.get_account(&a.swig_address).unwrap();
    assert_eq!(
        send(&mut context, &[legacy], &[&owner]).unwrap_err(),
        TransactionError::InstructionError(
            1,
            InstructionError::Custom(SwigError::InvalidSeedSwigAccount as u32)
        )
    );
    assert_eq!(context.svm.get_account(&a.swig_address).unwrap(), before);
    assert!(context.svm.get_account(&legacy_child).is_none());
}

#[test]
fn reservation_recovers_config_owned_tokens_and_closes_their_accounts() {
    use litesvm_token::spl_token;
    use solana_sdk::program_pack::Pack;
    use swig_interface::{
        CloseTokenAccountV1Instruction, TransferAssetsV1Instruction, TransferAssetsV1SplMigration,
    };
    let mut context = setup_test_context().unwrap();
    let owner = Keypair::new();
    let reservation = ed_reservation(&owner);
    let a = reservation.addresses().unwrap();
    let payer = context.default_payer.pubkey();
    let create = reservation.create_instruction(payer).unwrap();
    send(&mut context, &[create], &[]).unwrap();
    let mint = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let source = setup_ata(
        &mut context.svm,
        &mint,
        &a.swig_address,
        &context.default_payer,
    )
    .unwrap();
    let destination = setup_ata(
        &mut context.svm,
        &mint,
        &a.wallet_address,
        &context.default_payer,
    )
    .unwrap();
    mint_to(&mut context.svm, &mint, &context.default_payer, &source, 7).unwrap();
    let migrate = TransferAssetsV1Instruction::new_with_ed25519_authority_and_migrations(
        a.swig_address,
        a.wallet_address,
        payer,
        owner.pubkey(),
        0,
        &[TransferAssetsV1SplMigration::new(
            source,
            destination,
            spl_token::ID,
        )],
    )
    .unwrap();
    send(&mut context, &[migrate], &[&owner]).unwrap();
    assert_eq!(
        spl_token::state::Account::unpack(&context.svm.get_account(&destination).unwrap().data)
            .unwrap()
            .amount,
        7
    );
    let close = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        a.swig_address,
        a.wallet_address,
        owner.pubkey(),
        payer,
        spl_token::ID,
        vec![source],
        0,
    )
    .unwrap();
    send(&mut context, &[close], &[&owner]).unwrap();
    assert!(context.svm.get_account(&source).is_none());
}
