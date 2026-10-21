mod common;

use common::*;
use developer_account_registry::error::DeveloperAccountRegistryError;

fn update_signer_ix(address: Pubkey, signer: Pubkey) -> Instruction {
    UpdateDeveloperSignerInstruction::new(address, registry_admin(), signer).unwrap()
}

#[test]
fn replaces_only_the_signer() {
    let mut context = setup_test_context();
    let address = create_account(&mut context, random_id());
    let before = account(&context, &address).unwrap();
    let signer = Pubkey::new_unique();

    send(&mut context, update_signer_ix(address, signer)).unwrap();

    let after = account(&context, &address).unwrap();
    assert_eq!(after.data[..40], before.data[..40]);
    assert_eq!(after.data[40..72], signer.to_bytes());
    assert_eq!(after.data[72..80], before.data[72..80]);
    assert_eq!(after.lamports, before.lamports);
    assert_eq!(after.owner, program_id());
}

#[test]
fn create_or_update_keeps_the_registered_signer() {
    let mut context = setup_test_context();
    let id = random_id();
    let address = create_account(&mut context, id);
    let signer = Pubkey::new_unique();
    send(&mut context, update_signer_ix(address, signer)).unwrap();

    let ix = create_or_update_ix(&context, id, DeveloperTier::Free, 0);
    send(&mut context, ix).unwrap();

    let data = account(&context, &address).unwrap().data;
    assert_eq!(data[40..72], signer.to_bytes());
    assert_eq!(data[3], DeveloperTier::Free as u8);
    assert_eq!(data[72..80], 0i64.to_le_bytes());
}

#[test]
fn rejects_an_account_that_does_not_exist() {
    let mut context = setup_test_context();
    let (address, _) = developer_account_address(&random_id());

    assert_registry_error(
        send(
            &mut context,
            update_signer_ix(address, Pubkey::new_unique()),
        ),
        DeveloperAccountRegistryError::InvalidAccountOwner,
    );
    assert!(account(&context, &address).is_none());
}

#[test]
fn rejects_an_account_not_owned_by_the_registry() {
    let mut context = setup_test_context();
    let (address, _) = developer_account_address(&random_id());
    let foreign = Account {
        lamports: 1_000_000_000,
        data: vec![0u8; 80],
        owner: Pubkey::new_unique(),
        executable: false,
        rent_epoch: 0,
    };
    context.svm.set_account(address, foreign.clone()).unwrap();

    assert_registry_error(
        send(
            &mut context,
            update_signer_ix(address, Pubkey::new_unique()),
        ),
        DeveloperAccountRegistryError::InvalidAccountOwner,
    );
    assert_eq!(account(&context, &address).unwrap(), foreign);
}

#[test]
fn rejects_a_zero_signer() {
    let mut context = setup_test_context();
    let address = create_account(&mut context, random_id());
    let before = account(&context, &address).unwrap();

    assert_registry_error(
        send(&mut context, update_signer_ix(address, Pubkey::default())),
        DeveloperAccountRegistryError::InvalidSigner,
    );
    assert_eq!(account(&context, &address).unwrap(), before);
}

#[test]
fn rejects_a_wrong_or_unsigned_admin() {
    let mut context = setup_test_context();
    let address = create_account(&mut context, random_id());
    let before = account(&context, &address).unwrap();

    let mut wrong_admin = update_signer_ix(address, Pubkey::new_unique());
    wrong_admin.accounts[1].pubkey = Pubkey::new_unique();
    assert_registry_error(
        send(&mut context, wrong_admin),
        DeveloperAccountRegistryError::InvalidRegistryAdmin,
    );

    let mut unsigned_admin = update_signer_ix(address, Pubkey::new_unique());
    unsigned_admin.accounts[1].is_signer = false;
    assert_registry_error(
        send(&mut context, unsigned_admin),
        DeveloperAccountRegistryError::MissingRegistryAdminSignature,
    );

    assert_eq!(account(&context, &address).unwrap(), before);
}

#[test]
fn rejects_a_read_only_developer_account() {
    let mut context = setup_test_context();
    let address = create_account(&mut context, random_id());
    let before = account(&context, &address).unwrap();

    let mut ix = update_signer_ix(address, Pubkey::new_unique());
    ix.accounts[0].is_writable = false;

    assert_registry_error(
        send(&mut context, ix),
        DeveloperAccountRegistryError::AccountNotWritable,
    );
    assert_eq!(account(&context, &address).unwrap(), before);
}

#[test]
fn rejects_malformed_instruction_data() {
    let mut context = setup_test_context();
    let address = create_account(&mut context, random_id());
    let before = account(&context, &address).unwrap();

    for len in [39, 41] {
        let mut ix = update_signer_ix(address, Pubkey::new_unique());
        ix.data.resize(len, 0);
        assert_registry_error(
            send(&mut context, ix),
            DeveloperAccountRegistryError::InvalidInstructionDataLength,
        );
    }

    for offset in 2..8 {
        let mut ix = update_signer_ix(address, Pubkey::new_unique());
        ix.data[offset] = 1;
        assert_registry_error(
            send(&mut context, ix),
            DeveloperAccountRegistryError::InvalidInstructionPadding,
        );
    }

    assert_eq!(account(&context, &address).unwrap(), before);
}

#[test]
fn rejects_corrupted_stored_bytes() {
    let mut context = setup_test_context();
    let cases: [(fn(&mut Vec<u8>), DeveloperAccountRegistryError); 4] = [
        (
            |data| data[0] = 2,
            DeveloperAccountRegistryError::InvalidDiscriminator,
        ),
        (
            |data| data[2] = data[2].wrapping_sub(1),
            DeveloperAccountRegistryError::InvalidDeveloperAccountPda,
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
        let address = create_account(&mut context, random_id());
        let mut data = account(&context, &address).unwrap().data;
        corrupt(&mut data);
        overwrite_data(&mut context, &address, data);
        let before = account(&context, &address).unwrap();

        assert_registry_error(
            send(
                &mut context,
                update_signer_ix(address, Pubkey::new_unique()),
            ),
            expected,
        );
        assert_eq!(account(&context, &address).unwrap(), before);
    }
}
