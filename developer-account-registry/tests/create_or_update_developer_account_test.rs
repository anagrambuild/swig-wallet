mod common;

use common::*;
use developer_account_registry::error::DeveloperAccountRegistryError;
use solana_system_interface::program::ID as SYSTEM_PROGRAM_ID;

const VALID_UNTIL: i64 = 2_000_000_000;

fn pro_ix(context: &RegistryTestContext, id: [u8; 32]) -> Instruction {
    create_or_update_ix(context, id, DeveloperTier::Pro, VALID_UNTIL)
}

#[test]
fn creates_an_account_with_no_signer() {
    let mut context = setup_test_context();
    let id = random_id();
    let (address, _) = developer_account_address(&id);
    let payer = context.payer.pubkey();
    let payer_before = lamports(&context, &payer);

    let ix = pro_ix(&context, id);
    send(&mut context, ix).unwrap();

    let created = account(&context, &address).unwrap();
    assert_eq!(created.owner, program_id());
    assert_eq!(
        created.data,
        expected_image(id, DeveloperTier::Pro, VALID_UNTIL)
    );
    assert_eq!(created.lamports, rent(&context, 80));
    assert_eq!(
        payer_before - lamports(&context, &payer),
        rent(&context, 80) + 2 * FEE_PER_SIGNATURE
    );
}

#[test]
fn creates_when_the_payer_is_the_admin() {
    let mut context = setup_test_context();
    let id = random_id();
    let (address, _) = developer_account_address(&id);
    let ix = CreateOrUpdateDeveloperAccountInstruction::new(
        address,
        registry_admin(),
        registry_admin(),
        id,
        DeveloperTier::Enterprise,
        VALID_UNTIL,
    )
    .unwrap();

    send_from(&mut context, &registry_admin(), ix).unwrap();

    assert_eq!(
        account(&context, &address).unwrap().data,
        expected_image(id, DeveloperTier::Enterprise, VALID_UNTIL)
    );
}

#[test]
fn creation_tolerates_a_pre_funded_pda() {
    let mut context = setup_test_context();
    let full_rent = rent(&context, 80);
    for prefund in [1, full_rent, full_rent + 1_000_000_000] {
        let id = random_id();
        let (address, _) = developer_account_address(&id);
        // `airdrop` rejects a balance below rent exemption, so set it directly.
        let prefunded = Account {
            lamports: prefund,
            data: vec![],
            owner: SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        };
        context.svm.set_account(address, prefunded).unwrap();
        let payer = context.payer.pubkey();
        let payer_before = lamports(&context, &payer);

        let ix = pro_ix(&context, id);
        send(&mut context, ix).unwrap();

        let shortfall = full_rent.saturating_sub(prefund);
        assert_eq!(
            payer_before - lamports(&context, &payer),
            shortfall + 2 * FEE_PER_SIGNATURE,
            "prefund {prefund}"
        );
        assert_eq!(lamports(&context, &address), prefund.max(full_rent));
        assert_eq!(account(&context, &address).unwrap().owner, program_id());
    }
}

#[test]
fn creation_matches_the_golden_pda_vector() {
    let mut context = setup_test_context();
    let id = [0x11u8; 32];
    let expected_address = Pubkey::from_str_const("FGGb5a9BhzPnw7frXaTsFujFVMR7Sy3P6REEsRz2tovQ");
    let expected_bump = 255;

    let (address, bump) = developer_account_address(&id);
    assert_eq!((address, bump), (expected_address, expected_bump));

    let ix = pro_ix(&context, id);
    send(&mut context, ix).unwrap();
    assert_eq!(account(&context, &address).unwrap().data[2], expected_bump);
}

#[test]
fn update_replaces_only_the_subscription_fields() {
    let mut context = setup_test_context();
    let id = random_id();
    let address = create_account(&mut context, id);
    let mut data = account(&context, &address).unwrap().data;
    data[40..72].copy_from_slice(&[9u8; 32]);
    overwrite_data(&mut context, &address, data);
    let before = account(&context, &address).unwrap();
    let payer = context.payer.pubkey();
    let payer_before = lamports(&context, &payer);

    let ix = create_or_update_ix(&context, id, DeveloperTier::Ultra, 7);
    send(&mut context, ix).unwrap();

    let after = account(&context, &address).unwrap();
    assert_eq!(after.data[..3], before.data[..3]);
    assert_eq!(after.data[3], DeveloperTier::Ultra as u8);
    assert_eq!(after.data[4..72], before.data[4..72]);
    assert_eq!(after.data[72..80], 7i64.to_le_bytes());
    assert_eq!(after.lamports, before.lamports);
    assert_eq!(
        payer_before - lamports(&context, &payer),
        2 * FEE_PER_SIGNATURE
    );
}

#[test]
fn accepts_any_valid_until() {
    let mut context = setup_test_context();
    for valid_until in [0, -1, 1_000, i64::MAX] {
        let id = random_id();
        let ix = create_or_update_ix(&context, id, DeveloperTier::Pro, valid_until);
        send(&mut context, ix).unwrap();

        let data = account(&context, &developer_account_address(&id).0)
            .unwrap()
            .data;
        assert_eq!(data[72..80], valid_until.to_le_bytes());
    }
}

#[test]
fn rejects_an_update_whose_id_does_not_match_the_account() {
    let mut context = setup_test_context();
    let address = create_account(&mut context, random_id());
    let before = account(&context, &address).unwrap();

    let mut ix = pro_ix(&context, random_id());
    ix.accounts[0].pubkey = address;

    assert_registry_error(
        send(&mut context, ix),
        DeveloperAccountRegistryError::InvalidDeveloperAccountPda,
    );
    assert_eq!(account(&context, &address).unwrap(), before);
}

#[test]
fn rejects_an_account_that_is_neither_empty_nor_registry_owned() {
    let mut context = setup_test_context();
    let foreign_owner = Pubkey::new_unique();
    for (owner, data) in [
        (SYSTEM_PROGRAM_ID, vec![7u8; 16]),
        (foreign_owner, vec![0u8; 165]),
    ] {
        let id = random_id();
        let (address, _) = developer_account_address(&id);
        let existing = Account {
            lamports: 1_000_000,
            data,
            owner,
            executable: false,
            rent_epoch: 0,
        };
        context.svm.set_account(address, existing.clone()).unwrap();
        let payer = context.payer.pubkey();
        let payer_before = lamports(&context, &payer);

        let ix = pro_ix(&context, id);
        assert_registry_error(
            send(&mut context, ix),
            DeveloperAccountRegistryError::InvalidAccountState,
        );
        assert_eq!(account(&context, &address).unwrap(), existing);
        assert_eq!(
            payer_before - lamports(&context, &payer),
            2 * FEE_PER_SIGNATURE
        );
    }
}

#[test]
fn rejects_a_wrong_admin() {
    let mut context = setup_test_context();
    let id = random_id();
    let mut ix = pro_ix(&context, id);
    ix.accounts[1].pubkey = Pubkey::new_unique();

    assert_registry_error(
        send(&mut context, ix),
        DeveloperAccountRegistryError::InvalidRegistryAdmin,
    );
    assert!(account(&context, &developer_account_address(&id).0).is_none());
}

#[test]
fn rejects_an_admin_that_did_not_sign() {
    let mut context = setup_test_context();
    let id = random_id();
    let address = create_account(&mut context, id);
    let before = account(&context, &address).unwrap();

    let mut ix = pro_ix(&context, id);
    ix.accounts[1].is_signer = false;

    assert_registry_error(
        send(&mut context, ix),
        DeveloperAccountRegistryError::MissingRegistryAdminSignature,
    );
    assert_eq!(account(&context, &address).unwrap(), before);
}

#[test]
fn rejects_a_payer_that_is_not_a_writable_signer() {
    let mut context = setup_test_context();
    let id = random_id();
    let (address, _) = developer_account_address(&id);
    // With the PDA fully funded the Transfer CPI is skipped, so only the
    // program's own check enforces the payer flags.
    let full_rent = rent(&context, 80);
    context.svm.airdrop(&address, full_rent).unwrap();
    let other_payer = Pubkey::new_unique();
    context.svm.airdrop(&other_payer, 1_000_000_000).unwrap();

    for (is_signer, is_writable) in [(false, true), (true, false)] {
        let mut ix = pro_ix(&context, id);
        ix.accounts[2] = AccountMeta {
            pubkey: other_payer,
            is_signer,
            is_writable,
        };

        assert_registry_error(
            send(&mut context, ix),
            DeveloperAccountRegistryError::PayerMustBeWritableSigner,
        );
        let unchanged = account(&context, &address).unwrap();
        assert_eq!(unchanged.owner, SYSTEM_PROGRAM_ID);
        assert!(unchanged.data.is_empty());
    }
}

#[test]
fn rejects_a_wrong_system_program() {
    let mut context = setup_test_context();
    let id = random_id();
    let mut ix = pro_ix(&context, id);
    ix.accounts[3].pubkey = Pubkey::new_unique();

    assert_registry_error(
        send(&mut context, ix),
        DeveloperAccountRegistryError::InvalidSystemProgram,
    );
    assert!(account(&context, &developer_account_address(&id).0).is_none());
}

#[test]
fn rejects_an_address_derived_from_another_id() {
    let mut context = setup_test_context();
    let id = random_id();
    let other_address = developer_account_address(&random_id()).0;
    let mut ix = pro_ix(&context, id);
    ix.accounts[0].pubkey = other_address;

    assert_registry_error(
        send(&mut context, ix),
        DeveloperAccountRegistryError::InvalidDeveloperAccountPda,
    );
    assert!(account(&context, &other_address).is_none());
}

#[test]
fn rejects_a_non_canonical_bump_address() {
    let mut context = setup_test_context();
    let id = random_id();
    let (_, canonical_bump) = developer_account_address(&id);
    let non_canonical = (0..canonical_bump)
        .rev()
        .find_map(|bump| {
            Pubkey::create_program_address(
                &[b"developer-account", id.as_ref(), &[bump]],
                &program_id(),
            )
            .ok()
        })
        .expect("a lower valid bump exists for almost every id");
    let mut ix = pro_ix(&context, id);
    ix.accounts[0].pubkey = non_canonical;

    assert_registry_error(
        send(&mut context, ix),
        DeveloperAccountRegistryError::InvalidDeveloperAccountPda,
    );
    assert!(account(&context, &non_canonical).is_none());
}

#[test]
fn rejects_invalid_payload_fields() {
    let mut context = setup_test_context();

    let zero_id_ix = pro_ix(&context, [0u8; 32]);
    assert_registry_error(
        send(&mut context, zero_id_ix),
        DeveloperAccountRegistryError::InvalidDeveloperAccountId,
    );

    let id = random_id();
    let mut ix = pro_ix(&context, id);
    ix.data[2] = 4;
    assert_registry_error(
        send(&mut context, ix),
        DeveloperAccountRegistryError::InvalidTier,
    );
    assert!(account(&context, &developer_account_address(&id).0).is_none());
}

#[test]
fn rejects_malformed_instruction_data() {
    let mut context = setup_test_context();
    let id = random_id();

    for len in [47, 49] {
        let mut ix = pro_ix(&context, id);
        ix.data.resize(len, 0);
        assert_registry_error(
            send(&mut context, ix),
            DeveloperAccountRegistryError::InvalidInstructionDataLength,
        );
    }

    for offset in 3..8 {
        let mut ix = pro_ix(&context, id);
        ix.data[offset] = 1;
        assert_registry_error(
            send(&mut context, ix),
            DeveloperAccountRegistryError::InvalidInstructionPadding,
        );
    }

    let mut unknown = pro_ix(&context, id);
    unknown.data[..2].copy_from_slice(&1u16.to_le_bytes());
    assert_instruction_error(
        send(&mut context, unknown),
        InstructionError::InvalidInstructionData,
    );

    let mut truncated = pro_ix(&context, id);
    truncated.data.truncate(1);
    assert_instruction_error(
        send(&mut context, truncated),
        InstructionError::InvalidInstructionData,
    );

    assert!(account(&context, &developer_account_address(&id).0).is_none());
}

#[test]
// The runtime still reports a short account slice as `NotEnoughAccountKeys`.
#[allow(deprecated)]
fn rejects_a_short_account_list() {
    let mut context = setup_test_context();
    let id = random_id();
    let mut ix = pro_ix(&context, id);
    ix.accounts.pop();

    assert_instruction_error(
        send(&mut context, ix),
        InstructionError::NotEnoughAccountKeys,
    );
    assert!(account(&context, &developer_account_address(&id).0).is_none());
}

#[test]
fn rejects_a_read_only_developer_account() {
    let mut context = setup_test_context();
    let id = random_id();
    let address = create_account(&mut context, id);
    let before = account(&context, &address).unwrap();

    let mut ix = pro_ix(&context, id);
    ix.accounts[0].is_writable = false;

    assert_registry_error(
        send(&mut context, ix),
        DeveloperAccountRegistryError::AccountNotWritable,
    );
    assert_eq!(account(&context, &address).unwrap(), before);
}

#[test]
fn rejects_an_update_of_corrupted_stored_bytes() {
    let mut context = setup_test_context();
    let cases: [(fn(&mut Vec<u8>), DeveloperAccountRegistryError); 8] = [
        (
            |data| data[0] = 2,
            DeveloperAccountRegistryError::InvalidDiscriminator,
        ),
        (
            |data| data[1] = 2,
            DeveloperAccountRegistryError::UnsupportedVersion,
        ),
        (
            |data| data[2] = data[2].wrapping_sub(1),
            DeveloperAccountRegistryError::InvalidDeveloperAccountPda,
        ),
        (
            |data| data[3] = 4,
            DeveloperAccountRegistryError::InvalidTier,
        ),
        (
            |data| data[6] = 1,
            DeveloperAccountRegistryError::InvalidAccountPadding,
        ),
        (
            |data| data[8..40].fill(0),
            DeveloperAccountRegistryError::InvalidDeveloperAccountId,
        ),
        (
            |data| data[8] ^= 0xff,
            DeveloperAccountRegistryError::InvalidDeveloperAccountPda,
        ),
        (
            |data| data.truncate(79),
            DeveloperAccountRegistryError::InvalidAccountLength,
        ),
    ];

    for (corrupt, expected) in cases {
        let id = random_id();
        let address = create_account(&mut context, id);
        let mut data = account(&context, &address).unwrap().data;
        corrupt(&mut data);
        overwrite_data(&mut context, &address, data);
        let before = account(&context, &address).unwrap();

        let ix = pro_ix(&context, id);
        assert_registry_error(send(&mut context, ix), expected);
        assert_eq!(account(&context, &address).unwrap(), before);
    }
}
