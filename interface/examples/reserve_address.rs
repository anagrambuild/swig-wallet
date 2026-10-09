use solana_sdk::pubkey::Pubkey;
use swig_interface::reservation::{ReservationAddressOptions, ReservationV1};
use swig_state::authority::AuthorityType;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Public reference key from the design vectors; no signer or RPC is needed.
    let owner = Pubkey::new_from_array([
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ]);
    let program_id = Pubkey::new_from_array(swig_interface::swig::ID);
    let reservation = ReservationV1::new(
        program_id,
        AuthorityType::Ed25519,
        owner.as_ref(),
        ReservationAddressOptions::default(),
    )?;
    let addresses = reservation.addresses()?;
    let backup = reservation.package_bytes.clone();
    let restored = ReservationV1::from_bytes(&backup, program_id)?;
    if restored.addresses()?.wallet_address != addresses.wallet_address {
        return Err("restored reservation differs from the verified address".into());
    }

    println!("Reserved wallet address: {}", addresses.wallet_address);
    let payer = Pubkey::new_unique();
    let create = restored.create_instruction(payer)?;
    println!("Activation package: {} bytes", backup.len());
    println!(
        "CreateReservedV1: {} instruction bytes, {} accounts; external payer signs",
        create.data.len(),
        create.accounts.len()
    );
    // Submit this instruction with a 600,000-unit compute budget, or use
    // SwigWallet::from_reservation, which supplies the budget and transaction.

    Ok(())
}
