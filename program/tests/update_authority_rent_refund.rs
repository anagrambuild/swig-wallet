#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, RemoveAuthorityInstruction, UpdateAuthorityData,
    UpdateAuthorityInstruction,
};
use swig_state::{
    action::{all::All, sol_limit::SolLimit, Permission},
    authority::AuthorityType,
};

#[test]
fn shrinking_actions_refunds_only_released_rent_and_preserves_surplus() {
    for operation in [
        UpdateAuthorityData::ReplaceAll(vec![ClientAction::All(All {})]),
        UpdateAuthorityData::RemoveActionsByType(vec![Permission::SolLimit as u8]),
        UpdateAuthorityData::RemoveActionsByIndex(vec![1]),
    ] {
        let mut context = setup_test_context().unwrap();
        let root = Keypair::new();
        let target = Keypair::new();
        let refund_payer = Keypair::new();
        context
            .svm
            .airdrop(&refund_payer.pubkey(), 1_000_000_000)
            .unwrap();
        let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
        add_authority_with_ed25519_root(
            &mut context,
            &swig,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: target.pubkey().as_ref(),
            },
            vec![
                ClientAction::All(All {}),
                ClientAction::SolLimit(SolLimit { amount: 1 }),
            ],
        )
        .unwrap();
        context.svm.airdrop(&swig, 1_000_000_000).unwrap();
        let before = context.svm.get_account(&swig).unwrap();
        let before_payer = context.svm.get_account(&refund_payer.pubkey()).unwrap();
        let rent = context.svm.get_sysvar::<solana_sdk::rent::Rent>();
        let surplus = before.lamports - rent.minimum_balance(before.data.len());
        let instruction = UpdateAuthorityInstruction::new_with_ed25519_authority(
            swig,
            refund_payer.pubkey(),
            root.pubkey(),
            0,
            1,
            operation,
        )
        .unwrap();
        let message = v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[instruction],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();
        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[&context.default_payer, &refund_payer, &root],
        )
        .unwrap();
        let result = context.svm.send_transaction(tx);
        assert!(result.is_ok(), "{result:?}");
        let after = context.svm.get_account(&swig).unwrap();
        let after_payer = context.svm.get_account(&refund_payer.pubkey()).unwrap();
        assert!(after.data.len() < before.data.len());
        let released_rent =
            rent.minimum_balance(before.data.len()) - rent.minimum_balance(after.data.len());
        assert_eq!(after_payer.lamports - before_payer.lamports, released_rent);
        assert_eq!(
            after.lamports - rent.minimum_balance(after.data.len()),
            surplus
        );
    }
}

#[test]
fn growth_and_removal_preserve_configuration_sol_through_the_full_lifecycle() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new();
    let delegate = Keypair::new();
    let refund_payer = Keypair::new();
    context
        .svm
        .airdrop(&refund_payer.pubkey(), 1_000_000_000)
        .unwrap();
    let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
    context.svm.airdrop(&swig, 1_000_000_000).unwrap();
    let rent = context.svm.get_sysvar::<solana_sdk::rent::Rent>();
    let initial = context.svm.get_account(&swig).unwrap();
    let surplus = initial.lamports - rent.minimum_balance(initial.data.len());
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: delegate.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();
    let added = context.svm.get_account(&swig).unwrap();
    assert_eq!(
        added.lamports - rent.minimum_balance(added.data.len()),
        surplus
    );

    let instructions = [
        UpdateAuthorityInstruction::new_with_ed25519_authority(
            swig,
            refund_payer.pubkey(),
            root.pubkey(),
            0,
            1,
            UpdateAuthorityData::AddActions(vec![ClientAction::SolLimit(SolLimit { amount: 1 })]),
        )
        .unwrap(),
        UpdateAuthorityInstruction::new_with_ed25519_authority(
            swig,
            refund_payer.pubkey(),
            root.pubkey(),
            0,
            1,
            UpdateAuthorityData::RemoveActionsByIndex(vec![1]),
        )
        .unwrap(),
        RemoveAuthorityInstruction::new_with_ed25519_authority(
            swig,
            refund_payer.pubkey(),
            root.pubkey(),
            0,
            1,
        )
        .unwrap(),
    ];
    for instruction in instructions {
        let before = context.svm.get_account(&swig).unwrap();
        let payer_before = context
            .svm
            .get_account(&refund_payer.pubkey())
            .unwrap()
            .lamports;
        let message = v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[instruction],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();
        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[&context.default_payer, &refund_payer, &root],
        )
        .unwrap();
        let result = context.svm.send_transaction(tx);
        assert!(result.is_ok(), "{result:?}");
        let after = context.svm.get_account(&swig).unwrap();
        let payer_after = context
            .svm
            .get_account(&refund_payer.pubkey())
            .unwrap()
            .lamports;
        assert_eq!(
            after.lamports - rent.minimum_balance(after.data.len()),
            surplus
        );
        assert_eq!(
            i128::from(payer_after) - i128::from(payer_before),
            i128::from(rent.minimum_balance(before.data.len()))
                - i128::from(rent.minimum_balance(after.data.len())),
        );
    }
    let final_account = context.svm.get_account(&swig).unwrap();
    assert_eq!(final_account.data.len(), initial.data.len());
    assert_eq!(final_account.lamports, initial.lamports);
}

struct RefundFixture {
    context: SwigTestContext,
    root: Keypair,
    payer: Keypair,
    claimer: solana_sdk::pubkey::Pubkey,
    swig: solana_sdk::pubkey::Pubkey,
}

impl RefundFixture {
    fn new(claimer_is_payer: bool) -> Self {
        let mut context = setup_test_context().unwrap();
        let root = Keypair::new();
        let target = Keypair::new();
        let payer = Keypair::new();
        let claimer = if claimer_is_payer {
            payer.pubkey()
        } else {
            Keypair::new().pubkey()
        };
        context.svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
        context.svm.airdrop(&claimer, 1_000_000).unwrap();
        let (swig, _) = create_swig_ed25519(&mut context, &root, rand::random()).unwrap();
        add_authority_with_ed25519_root(
            &mut context,
            &swig,
            &root,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: target.pubkey().as_ref(),
            },
            vec![
                ClientAction::All(All {}),
                ClientAction::SolLimit(SolLimit { amount: 1 }),
            ],
        )
        .unwrap();
        set_rent_claimer_with_ed25519(&mut context, &swig, &root, 0, claimer).unwrap();
        context.svm.airdrop(&swig, 1_000_000_000).unwrap();
        Self {
            context,
            root,
            payer,
            claimer,
            swig,
        }
    }

    fn instruction(
        &self,
        operation: Option<UpdateAuthorityData>,
    ) -> solana_sdk::instruction::Instruction {
        let accounts = swig_interface::AuthorityRentAccounts {
            payer: self.payer.pubkey(),
            rent_claimer: Some(self.claimer),
        };
        match operation {
            Some(operation) => UpdateAuthorityInstruction::new_with_ed25519_authority(
                self.swig,
                accounts,
                self.root.pubkey(),
                0,
                1,
                operation,
            )
            .unwrap(),
            None => RemoveAuthorityInstruction::new_with_ed25519_authority(
                self.swig,
                accounts,
                self.root.pubkey(),
                0,
                1,
            )
            .unwrap(),
        }
    }

    fn send(
        &mut self,
        instructions: &[solana_sdk::instruction::Instruction],
    ) -> Result<litesvm::types::TransactionMetadata, Box<litesvm::types::FailedTransactionMetadata>>
    {
        self.context.svm.expire_blockhash();
        let message = v0::Message::try_compile(
            &self.context.default_payer.pubkey(),
            instructions,
            &[],
            self.context.svm.latest_blockhash(),
        )
        .unwrap();
        let mut signers = vec![&self.context.default_payer, &self.payer];
        if instructions.iter().any(|instruction| {
            instruction
                .accounts
                .iter()
                .any(|account| account.pubkey == self.root.pubkey() && account.is_signer)
        }) {
            signers.push(&self.root);
        }
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &signers).unwrap();
        self.context.svm.send_transaction(tx).map_err(Box::new)
    }

    fn assert_refund(&mut self, instructions: &[solana_sdk::instruction::Instruction]) {
        let before = self.context.svm.get_account(&self.swig).unwrap();
        let payer_before = self.context.svm.get_balance(&self.payer.pubkey()).unwrap();
        let claimer_before = self.context.svm.get_balance(&self.claimer).unwrap();
        let rent = self.context.svm.get_sysvar::<solana_sdk::rent::Rent>();
        self.send(instructions).unwrap();
        let after = self.context.svm.get_account(&self.swig).unwrap();
        let released =
            rent.minimum_balance(before.data.len()) - rent.minimum_balance(after.data.len());
        assert!(released > 0);
        assert_eq!(
            self.context.svm.get_balance(&self.claimer).unwrap() - claimer_before,
            released
        );
        assert_eq!(
            self.context.svm.get_balance(&self.payer.pubkey()).unwrap(),
            payer_before
                + if self.claimer == self.payer.pubkey() {
                    released
                } else {
                    0
                }
        );
        assert_eq!(
            after.lamports - rent.minimum_balance(after.data.len()),
            before.lamports - rent.minimum_balance(before.data.len())
        );
    }
}

#[test]
fn configured_claimer_receives_all_shrink_modes_and_role_removal_refunds() {
    for operation in [
        Some(UpdateAuthorityData::ReplaceAll(vec![ClientAction::All(
            All {},
        )])),
        Some(UpdateAuthorityData::RemoveActionsByType(vec![
            Permission::SolLimit as u8,
        ])),
        Some(UpdateAuthorityData::RemoveActionsByIndex(vec![1])),
        None,
    ] {
        let mut fixture = RefundFixture::new(false);
        let instruction = fixture.instruction(operation);
        assert_eq!(instruction.accounts[3].pubkey, fixture.root.pubkey());
        assert_eq!(instruction.accounts[4].pubkey, fixture.claimer);
        assert!(!instruction.accounts[4].is_signer);
        fixture.assert_refund(&[instruction]);
    }
}

#[test]
fn invalid_refund_destinations_reject_without_mutation() {
    use solana_sdk::{
        instruction::{AccountMeta, InstructionError},
        transaction::TransactionError,
    };
    for removal in [false, true] {
        for invalid in ["missing", "wrong", "readonly", "config", "wallet", "zero"] {
            let mut fixture = RefundFixture::new(false);
            let operation = (!removal).then(|| UpdateAuthorityData::RemoveActionsByIndex(vec![1]));
            let mut instruction = fixture.instruction(operation);
            match invalid {
                "missing" => {
                    instruction.accounts.pop();
                },
                "wrong" => {
                    instruction.accounts.last_mut().unwrap().pubkey = Keypair::new().pubkey();
                },
                "readonly" => {
                    instruction.accounts.last_mut().unwrap().is_writable = false;
                },
                _ => {
                    let invalid_key = match invalid {
                        "config" => fixture.swig,
                        "wallet" => {
                            solana_sdk::pubkey::Pubkey::find_program_address(
                                &swig_state::swig::swig_wallet_address_seeds(fixture.swig.as_ref()),
                                &program_id(),
                            )
                            .0
                        },
                        _ => solana_sdk::pubkey::Pubkey::default(),
                    };
                    let mut account = fixture.context.svm.get_account(&fixture.swig).unwrap();
                    let tail_start =
                        swig_state::swig::Swig::roles_end_offset(&account.data).unwrap();
                    account.data[tail_start..].copy_from_slice(
                        &swig_state::tail::rent_claimer::entry(&invalid_key.to_bytes()),
                    );
                    fixture
                        .context
                        .svm
                        .set_account(fixture.swig, account)
                        .unwrap();
                    *instruction.accounts.last_mut().unwrap() =
                        AccountMeta::new(invalid_key, false);
                },
            }
            let before = fixture.context.svm.get_account(&fixture.swig).unwrap();
            let payer_before = fixture
                .context
                .svm
                .get_balance(&fixture.payer.pubkey())
                .unwrap();
            let claimer_before = fixture.context.svm.get_balance(&fixture.claimer).unwrap();
            let error = fixture.send(&[instruction]).unwrap_err();
            assert_eq!(
                error.err,
                TransactionError::InstructionError(0, InstructionError::Custom(61)),
                "{removal} {invalid}: {error:?}"
            );
            assert_eq!(
                fixture.context.svm.get_account(&fixture.swig).unwrap(),
                before
            );
            assert_eq!(
                fixture
                    .context
                    .svm
                    .get_balance(&fixture.payer.pubkey())
                    .unwrap(),
                payer_before
            );
            assert_eq!(
                fixture.context.svm.get_balance(&fixture.claimer).unwrap(),
                claimer_before
            );
        }
    }
}

#[test]
fn configured_claimer_does_not_require_an_extra_account_for_growth() {
    let mut fixture = RefundFixture::new(false);
    for operation in [
        UpdateAuthorityData::AddActions(vec![ClientAction::ManageAuthority(
            swig_state::action::manage_authority::ManageAuthority {},
        )]),
        UpdateAuthorityData::ReplaceAll(vec![
            ClientAction::All(All {}),
            ClientAction::SolLimit(SolLimit { amount: 3 }),
            ClientAction::ManageAuthority(swig_state::action::manage_authority::ManageAuthority {}),
        ]),
    ] {
        let instruction = UpdateAuthorityInstruction::new_with_ed25519_authority(
            fixture.swig,
            fixture.payer.pubkey(),
            fixture.root.pubkey(),
            0,
            1,
            operation,
        )
        .unwrap();
        let before = fixture.context.svm.get_account(&fixture.swig).unwrap();
        let rent = fixture.context.svm.get_sysvar::<solana_sdk::rent::Rent>();
        fixture.send(&[instruction]).unwrap();
        let after = fixture.context.svm.get_account(&fixture.swig).unwrap();
        assert_eq!(
            after.lamports - rent.minimum_balance(after.data.len()),
            before.lamports - rent.minimum_balance(before.data.len())
        );
    }
}

#[test]
fn secp256k1_refund_builders_sign_the_appended_claimer() {
    use alloy_primitives::B256;
    use alloy_signer::SignerSync;
    use alloy_signer_local::LocalSigner;
    for claimer_is_payer in [false, true] {
        let mut fixture = RefundFixture::new(claimer_is_payer);
        let signer = LocalSigner::random();
        let public_key = signer
            .credential()
            .verifying_key()
            .to_encoded_point(false)
            .to_bytes();
        add_authority_with_ed25519_root(
            &mut fixture.context,
            &fixture.swig,
            &fixture.root,
            AuthorityConfig {
                authority_type: AuthorityType::Secp256k1,
                authority: &public_key[1..],
            },
            vec![ClientAction::All(All {})],
        )
        .unwrap();
        let sign = |message: &[u8]| {
            signer
                .sign_hash_sync(&B256::from_slice(message))
                .unwrap()
                .as_bytes()
        };
        let accounts = swig_interface::AuthorityRentAccounts {
            payer: fixture.payer.pubkey(),
            rent_claimer: Some(fixture.claimer),
        };
        let slot = fixture
            .context
            .svm
            .get_sysvar::<solana_sdk::clock::Clock>()
            .slot;
        let update = UpdateAuthorityInstruction::new_with_secp256k1_authority(
            fixture.swig,
            accounts,
            sign,
            slot,
            1,
            2,
            1,
            UpdateAuthorityData::RemoveActionsByIndex(vec![1]),
        )
        .unwrap();
        fixture.assert_refund(&[update]);
        let remove = RemoveAuthorityInstruction::new_with_secp256k1_authority(
            fixture.swig,
            accounts,
            sign,
            slot,
            2,
            2,
            1,
        )
        .unwrap();
        fixture.assert_refund(&[remove]);
    }
}

#[test]
fn secp256r1_refund_builders_preserve_sysvar_index_and_sign_the_claimer() {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };
    let mut fixture = RefundFixture::new(false);
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let public_key: [u8; 33] = key
        .public_key()
        .to_bytes(
            &group,
            PointConversionForm::COMPRESSED,
            &mut BigNumContext::new().unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
    add_authority_with_ed25519_root(
        &mut fixture.context,
        &fixture.swig,
        &fixture.root,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &public_key,
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();
    let sign = |message: &[u8]| {
        solana_secp256r1_program::sign_message(message, &key.private_key_to_der().unwrap()).unwrap()
    };
    let accounts = swig_interface::AuthorityRentAccounts {
        payer: fixture.payer.pubkey(),
        rent_claimer: Some(fixture.claimer),
    };
    let slot = fixture
        .context
        .svm
        .get_sysvar::<solana_sdk::clock::Clock>()
        .slot;
    let update = UpdateAuthorityInstruction::new_with_secp256r1_authority(
        fixture.swig,
        accounts,
        sign,
        slot,
        1,
        2,
        1,
        UpdateAuthorityData::RemoveActionsByIndex(vec![1]),
        &public_key,
    )
    .unwrap();
    assert_eq!(
        update[1].accounts[3].pubkey,
        solana_sdk::sysvar::instructions::ID
    );
    fixture.assert_refund(&update);
    let remove = RemoveAuthorityInstruction::new_with_secp256r1_authority(
        fixture.swig,
        accounts,
        sign,
        slot,
        2,
        2,
        1,
        &public_key,
    )
    .unwrap();
    fixture.assert_refund(&remove);
}

#[test]
fn unfunded_claimer_rejects_small_refunds_without_mutation() {
    use solana_sdk::transaction::TransactionError;
    for removal in [false, true] {
        let mut fixture = RefundFixture::new(false);
        let mut claimer = fixture.context.svm.get_account(&fixture.claimer).unwrap();
        claimer.lamports = 0;
        fixture
            .context
            .svm
            .set_account(fixture.claimer, claimer)
            .unwrap();
        let instruction = fixture
            .instruction((!removal).then(|| UpdateAuthorityData::RemoveActionsByIndex(vec![1])));
        let before = fixture.context.svm.get_account(&fixture.swig).unwrap();
        let payer_before = fixture
            .context
            .svm
            .get_balance(&fixture.payer.pubkey())
            .unwrap();
        let claimer_before = fixture.context.svm.get_account(&fixture.claimer);
        let error = fixture.send(&[instruction]).unwrap_err();
        assert!(
            matches!(error.err, TransactionError::InsufficientFundsForRent { .. }),
            "{error:?}"
        );
        assert_eq!(
            fixture.context.svm.get_account(&fixture.swig).unwrap(),
            before
        );
        assert_eq!(
            fixture
                .context
                .svm
                .get_balance(&fixture.payer.pubkey())
                .unwrap(),
            payer_before
        );
        assert_eq!(
            fixture.context.svm.get_account(&fixture.claimer),
            claimer_before
        );
    }
}
