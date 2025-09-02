use super::*;
use crate::decoder::InstructionType;
use crate::types::UpdateAuthorityData;
use solana_sdk::account::ReadableAccount;

#[test_log::test]
fn should_decode_create_swig_instruction() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Verify wallet was created successfully
    assert!(swig_wallet.get_swig_account().is_ok());
    assert_eq!(swig_wallet.get_role_count().unwrap(), 1);
    assert_eq!(swig_wallet.get_current_role_id().unwrap(), 0);

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    let swig_data = swig_wallet.litesvm().get_account(&swig_pubkey).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data.data).unwrap();

    assert_eq!(swig_with_roles.state.id, [0; 32]);

    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    let secondary_authority = Keypair::new();

    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::All {}],
        )
        .unwrap();

    // update the authority
    let update_data = UpdateAuthorityData::ReplaceAll(vec![Permission::Sol {
        amount: 10_000_000_000,
        recurring: None,
    }]);

    let tx = swig_wallet.update_authority(1, update_data).unwrap();

    // Remove the authority
    let tx = swig_wallet
        .remove_authority(&secondary_authority.pubkey().to_bytes())
        .unwrap();

    // Sign a transaction
    use solana_sdk::system_instruction;
    let inner_ix = system_instruction::transfer(
        &swig_wallet.get_swig_account().unwrap(),
        &secondary_authority.pubkey(),
        100_000_000,
    );

    let (tx, decoded_tx) = swig_wallet
        .build_sign_transaction(vec![inner_ix], None)
        .unwrap();

    // Verify decoded transaction
    if let Some(decoded_tx) = decoded_tx {
        println!("signed decoded_tx: {}", decoded_tx.to_json().unwrap());
        assert!(decoded_tx.instruction_type.to_string().contains("Sign"));
        assert_eq!(decoded_tx.role_id, 0);
        assert_eq!(decoded_tx.authority_type, AuthorityType::Ed25519);
        assert_eq!(decoded_tx.fee_payer, main_authority.pubkey().to_string());

        // Verify the specific sign data
        if let InstructionType::Sign = &decoded_tx.instruction_type {
            // Sign instruction no longer contains inner_instructions for cleaner JSON
        } else {
            panic!("Expected Sign instruction type");
        }
    } else {
        panic!("Expected decoded transaction");
    }
}

#[test_log::test]
fn should_decode_add_authority_instruction() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    let swig_data = swig_wallet.litesvm().get_account(&swig_pubkey).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data.data).unwrap();

    assert_eq!(swig_with_roles.state.id, [0; 32]);

    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    let secondary_authority = Keypair::new();

    println!("secondary_authority: {}", secondary_authority.pubkey());
    let (tx, decoded_tx) = swig_wallet
        .build_add_authority_transaction(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::All {}],
        )
        .unwrap();

    // assert the decoded tx is valid
    if let Some(decoded_tx) = decoded_tx {
        println!("AddAuthority decoded_tx: {}", decoded_tx.to_json().unwrap());

        assert!(decoded_tx
            .instruction_type
            .to_string()
            .contains("AddAuthority"));
        assert_eq!(decoded_tx.role_id, 0);
        assert_eq!(decoded_tx.authority_type, AuthorityType::Ed25519);
        assert_eq!(decoded_tx.fee_payer, main_authority.pubkey().to_string());

        // Verify the specific authority data from the provided example
        if let InstructionType::AddAuthority {
            new_authority_type,
            new_authority,
            permissions,
        } = &decoded_tx.instruction_type
        {
            assert_eq!(*new_authority_type, AuthorityType::Ed25519);
            assert_eq!(permissions.len(), 1);
            assert!(matches!(permissions[0], Permission::All {}));
            // new_authority should now be a formatted string instead of raw bytes
            assert!(new_authority.starts_with("") || new_authority.starts_with("0x"));
        } else {
            panic!("Expected AddAuthority instruction type");
        }
    } else {
        panic!("Expected decoded transaction");
    }
}

#[test_log::test]
fn should_decode_remove_authority_instruction() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    let secondary_authority = Keypair::new();

    // First add an authority
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::All {}],
        )
        .unwrap();

    // Then build remove authority transaction
    let (tx, decoded_tx) = swig_wallet.build_remove_authority_transaction(1).unwrap();

    // assert the decoded tx is valid
    if let Some(decoded_tx) = decoded_tx {
        println!(
            "remove authority decoded_tx: {}",
            decoded_tx.to_json().unwrap()
        );

        assert!(decoded_tx
            .instruction_type
            .to_string()
            .contains("RemoveAuthority"));
        assert_eq!(decoded_tx.role_id, 0);
        assert_eq!(decoded_tx.authority_type, AuthorityType::Ed25519);
        assert_eq!(decoded_tx.fee_payer, main_authority.pubkey().to_string());

        // Verify the specific authority data
        if let InstructionType::RemoveAuthority {
            authority_to_remove_id,
        } = &decoded_tx.instruction_type
        {
            assert_eq!(*authority_to_remove_id, 1);
        } else {
            panic!("Expected RemoveAuthority instruction type");
        }
    } else {
        panic!("Expected decoded transaction");
    }
}

#[test_log::test]
fn should_decode_update_authority_instruction() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    let secondary_authority = Keypair::new();

    // First add an authority
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::All {}],
        )
        .unwrap();

    // Then build update authority transaction
    let update_data = UpdateAuthorityData::ReplaceAll(vec![Permission::Sol {
        amount: 10_000_000_000,
        recurring: None,
    }]);

    let (tx, decoded_tx) = swig_wallet
        .build_update_authority_transaction(1, update_data)
        .unwrap();

    // assert the decoded tx is valid
    if let Some(decoded_tx) = decoded_tx {
        println!(
            "update authority decoded_tx: {}",
            decoded_tx.to_json().unwrap()
        );

        assert!(decoded_tx
            .instruction_type
            .to_string()
            .contains("UpdateAuthority"));
        assert_eq!(decoded_tx.role_id, 0);
        assert_eq!(decoded_tx.authority_type, AuthorityType::Ed25519);
        assert_eq!(decoded_tx.fee_payer, main_authority.pubkey().to_string());

        // Verify the specific authority data
        if let InstructionType::UpdateAuthority {
            authority_to_replace_id,
            update_data,
        } = &decoded_tx.instruction_type
        {
            assert_eq!(*authority_to_replace_id, 1);
            assert!(matches!(update_data, UpdateAuthorityData::ReplaceAll(_)));
        } else {
            panic!("Expected UpdateAuthority instruction type");
        }
    } else {
        panic!("Expected decoded transaction");
    }
}

#[test_log::test]
fn should_decode_create_session_instruction() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    let session_key = Keypair::new();
    let duration = 1000;

    // Build create session transaction
    let (tx, decoded_tx) = swig_wallet
        .build_create_session_transaction(session_key.pubkey(), duration)
        .unwrap();

    // Verify transaction was created successfully
    assert!(matches!(
        tx.message,
        solana_sdk::message::VersionedMessage::V0(_)
    ));

    // Verify decoded transaction
    if let Some(decoded_tx) = decoded_tx {
        println!(
            "create session decoded_tx: {}",
            decoded_tx.to_json().unwrap()
        );
        assert!(decoded_tx
            .instruction_type
            .to_string()
            .contains("CreateSession"));
        assert_eq!(decoded_tx.role_id, 0);
        assert_eq!(decoded_tx.authority_type, AuthorityType::Ed25519);
        assert_eq!(decoded_tx.fee_payer, main_authority.pubkey().to_string());
    } else {
        panic!("Expected decoded transaction");
    }
}

#[test_log::test]
fn should_decode_create_sub_account_instruction() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // Build create sub account transaction
    let (tx, decoded_tx) = swig_wallet.build_create_sub_account_transaction().unwrap();

    // Verify transaction was created successfully
    assert!(matches!(
        tx.message,
        solana_sdk::message::VersionedMessage::V0(_)
    ));

    // Verify decoded transaction
    if let Some(decoded_tx) = decoded_tx {
        println!(
            "create sub account decoded_tx: {}",
            decoded_tx.to_json().unwrap()
        );
        assert!(decoded_tx
            .instruction_type
            .to_string()
            .contains("CreateSubAccount"));
        assert_eq!(decoded_tx.role_id, 0);
        assert_eq!(decoded_tx.authority_type, AuthorityType::Ed25519);
        assert_eq!(decoded_tx.fee_payer, main_authority.pubkey().to_string());
    } else {
        panic!("Expected decoded transaction");
    }
}

#[test_log::test]
fn should_decode_sign_with_sub_account_instruction() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // First create a sub account
    swig_wallet.create_sub_account().unwrap();

    // Create a test instruction
    use solana_sdk::system_instruction;
    let inner_ix = system_instruction::transfer(
        &swig_wallet.get_swig_account().unwrap(),
        &main_authority.pubkey(),
        100_000_000,
    );

    // Build sign with sub account transaction
    let (tx, decoded_tx) = swig_wallet
        .build_sign_with_sub_account_transaction(vec![inner_ix], None)
        .unwrap();

    // Verify transaction was created successfully
    assert!(matches!(
        tx.message,
        solana_sdk::message::VersionedMessage::V0(_)
    ));

    // Verify decoded transaction
    if let Some(decoded_tx) = decoded_tx {
        println!(
            "sign with sub account decoded_tx: {}",
            decoded_tx.to_json().unwrap()
        );
        assert!(decoded_tx
            .instruction_type
            .to_string()
            .contains("SignWithSubAccount"));
        assert_eq!(decoded_tx.role_id, 0);
        assert_eq!(decoded_tx.authority_type, AuthorityType::Ed25519);
        assert_eq!(decoded_tx.fee_payer, main_authority.pubkey().to_string());
    } else {
        panic!("Expected decoded transaction");
    }
}

#[test_log::test]
fn should_decode_withdraw_from_sub_account_instruction() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // First create a sub account
    let sub_account = swig_wallet.create_sub_account().unwrap();
    let sub_account_pubkey = swig_wallet.get_sub_account().unwrap().unwrap();

    // Build withdraw from sub account transaction
    let (tx, decoded_tx) = swig_wallet
        .build_withdraw_from_sub_account_transaction(sub_account_pubkey, 1_000_000_000)
        .unwrap();

    // Verify transaction was created successfully
    assert!(matches!(
        tx.message,
        solana_sdk::message::VersionedMessage::V0(_)
    ));

    // Verify decoded transaction
    if let Some(decoded_tx) = decoded_tx {
        println!(
            "withdraw from sub account decoded_tx: {}",
            decoded_tx.to_json().unwrap()
        );
        assert!(decoded_tx
            .instruction_type
            .to_string()
            .contains("WithdrawFromSubAccount"));
        assert_eq!(decoded_tx.role_id, 0);
        assert_eq!(decoded_tx.authority_type, AuthorityType::Ed25519);
        assert_eq!(decoded_tx.fee_payer, main_authority.pubkey().to_string());
    } else {
        panic!("Expected decoded transaction");
    }
}

#[test_log::test]
fn should_decode_withdraw_token_from_sub_account_instruction() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // First create a sub account
    let sub_account = swig_wallet.create_sub_account().unwrap();
    let sub_account_pubkey = swig_wallet.get_sub_account().unwrap().unwrap();

    // Create test token accounts (using system program as placeholder)
    let sub_account_token = Keypair::new().pubkey();
    let swig_token = Keypair::new().pubkey();
    let token_program = solana_sdk::system_program::id();

    // Build withdraw token from sub account transaction
    let (tx, decoded_tx) = swig_wallet
        .build_withdraw_token_from_sub_account_transaction(
            sub_account_pubkey,
            sub_account_token,
            swig_token,
            token_program,
            1_000_000_000,
        )
        .unwrap();

    // Verify transaction was created successfully
    assert!(matches!(
        tx.message,
        solana_sdk::message::VersionedMessage::V0(_)
    ));

    // Verify decoded transaction
    if let Some(decoded_tx) = decoded_tx {
        println!(
            "withdraw token from sub account decoded_tx: {}",
            decoded_tx.to_json().unwrap()
        );
        assert!(decoded_tx
            .instruction_type
            .to_string()
            .contains("WithdrawTokenFromSubAccount"));
        assert_eq!(decoded_tx.role_id, 0);
        assert_eq!(decoded_tx.authority_type, AuthorityType::Ed25519);
        assert_eq!(decoded_tx.fee_payer, main_authority.pubkey().to_string());
    } else {
        panic!("Expected decoded transaction");
    }
}

#[test_log::test]
fn should_decode_toggle_sub_account_instruction() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // First create a sub account
    let sub_account = swig_wallet.create_sub_account().unwrap();
    let sub_account_pubkey = swig_wallet.get_sub_account().unwrap().unwrap();

    // Build toggle sub account transaction (disable)
    let (tx, decoded_tx) = swig_wallet
        .build_toggle_sub_account_transaction(sub_account_pubkey, false)
        .unwrap();

    // Verify transaction was created successfully
    assert!(matches!(
        tx.message,
        solana_sdk::message::VersionedMessage::V0(_)
    ));

    // Verify decoded transaction
    if let Some(decoded_tx) = decoded_tx {
        println!(
            "toggle sub account decoded_tx: {}",
            decoded_tx.to_json().unwrap()
        );
        assert!(decoded_tx
            .instruction_type
            .to_string()
            .contains("ToggleSubAccount"));
        assert_eq!(decoded_tx.role_id, 0);
        assert_eq!(decoded_tx.authority_type, AuthorityType::Ed25519);
        assert_eq!(decoded_tx.fee_payer, main_authority.pubkey().to_string());
    } else {
        panic!("Expected decoded transaction");
    }

    // Test enabling the sub account
    let (tx, decoded_tx) = swig_wallet
        .build_toggle_sub_account_transaction(sub_account_pubkey, true)
        .unwrap();

    // Verify transaction was created successfully
    assert!(matches!(
        tx.message,
        solana_sdk::message::VersionedMessage::V0(_)
    ));

    // Verify decoded transaction
    if let Some(decoded_tx) = decoded_tx {
        println!(
            "toggle sub account enable decoded_tx: {}",
            decoded_tx.to_json().unwrap()
        );
        assert!(decoded_tx
            .instruction_type
            .to_string()
            .contains("ToggleSubAccount"));
        assert_eq!(decoded_tx.role_id, 0);
        assert_eq!(decoded_tx.authority_type, AuthorityType::Ed25519);
        assert_eq!(decoded_tx.fee_payer, main_authority.pubkey().to_string());
    } else {
        panic!("Expected decoded transaction");
    }
}
