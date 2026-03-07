use litesvm::LiteSVM;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
};

const DISCRIMINATOR: [u8; 8] = [0x76, 0x61, 0x6c, 0x74, 0x72, 0x61, 0x64, 0x65];

fn load_oracle(svm: &mut LiteSVM) -> Pubkey {
    let program_id =
        Pubkey::from_str_const("EQ2rR75Y9nzQVSVBC4Fb8p7p8xVdRsaAxdNYBLiGTZjp");
    let elf = std::fs::read("../target/deploy/slippage_oracle.so")
        .expect("slippage_oracle.so not found -- run `cargo build-sbf` first");
    svm.add_program(program_id, &elf);
    program_id
}

fn build_validate_trade_ix(
    program_id: Pubkey,
    swig_config: Pubkey,
    swig_wallet: Pubkey,
    input_amount: u64,
    min_output_amount: u64,
    min_bps: u16,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 18);
    data.extend_from_slice(&DISCRIMINATOR);
    data.extend_from_slice(&input_amount.to_le_bytes());
    data.extend_from_slice(&min_output_amount.to_le_bytes());
    data.extend_from_slice(&min_bps.to_le_bytes());

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(swig_config, false),
            AccountMeta::new_readonly(swig_wallet, false),
        ],
        data,
    }
}

#[test]
fn test_output_meets_min_bps() {
    let mut svm = LiteSVM::new();
    let program_id = load_oracle(&mut svm);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let swig_config = Pubkey::new_unique();
    let swig_wallet = Pubkey::new_unique();

    // 100 input, 99 output, 9900 bps (99%) -> required_min = 99, output == 99 -> pass
    let ix = build_validate_trade_ix(program_id, swig_config, swig_wallet, 100, 99, 9900);
    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);
    svm.send_transaction(tx).expect("should succeed: output meets min_bps");
}

#[test]
fn test_output_below_min_bps() {
    let mut svm = LiteSVM::new();
    let program_id = load_oracle(&mut svm);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let swig_config = Pubkey::new_unique();
    let swig_wallet = Pubkey::new_unique();

    // 100 input, 90 output, 9900 bps (99%) -> required_min = 99, output 90 < 99 -> fail
    let ix = build_validate_trade_ix(program_id, swig_config, swig_wallet, 100, 90, 9900);
    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);
    let result = svm.send_transaction(tx);
    assert!(result.is_err(), "should fail: output below min_bps (SlippageExceeded)");
}

#[test]
fn test_missing_accounts() {
    let mut svm = LiteSVM::new();
    let program_id = load_oracle(&mut svm);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    // Build instruction with no accounts
    let mut data = Vec::with_capacity(8 + 18);
    data.extend_from_slice(&DISCRIMINATOR);
    data.extend_from_slice(&100u64.to_le_bytes());
    data.extend_from_slice(&99u64.to_le_bytes());
    data.extend_from_slice(&9900u16.to_le_bytes());

    let ix = Instruction {
        program_id,
        accounts: vec![],
        data,
    };

    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);
    let result = svm.send_transaction(tx);
    assert!(result.is_err(), "should fail: missing accounts (InvalidAccountCount)");
}
