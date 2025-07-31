use super::*;
use crate::types::UpdateAuthorityData;

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
    let (tx, decoded_instruction) = swig_wallet
        .build_add_authority_transaction(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::All {}],
        )
        .unwrap();

    println!("added decoded_instruction: {:?}", decoded_instruction);

    // update the authority
    let update_data = UpdateAuthorityData::ReplaceAll(vec![Permission::Sol {
        amount: 10_000_000_000,
        recurring: None,
    }]);

    let (tx, decoded_instruction) = swig_wallet
        .build_update_authority_transaction(1, update_data)
        .unwrap();

    println!("updated decoded_instruction: {:?}", decoded_instruction);

    // Remove the authority
    let (tx, decoded_instruction) = swig_wallet.build_remove_authority_transaction(1).unwrap();

    println!("removed decoded_instruction: {:?}", decoded_instruction);

    // Sign a transaction
    use solana_sdk::system_instruction;
    let inner_ix = system_instruction::transfer(
        &swig_wallet.get_swig_account().unwrap(),
        &secondary_authority.pubkey(),
        100_000_000,
    );

    let (tx, decoded_instruction) = swig_wallet
        .build_sign_transaction(vec![inner_ix], None)
        .unwrap();

    println!("signed decoded_instruction: {:?}", decoded_instruction);

    let result = swig_wallet.litesvm().simulate_transaction(tx);
    println!("result: {:?}", result);
}
