# 💳 Swig Wallet Subscription Example

This example shows two common subscription scenarios:

1. User creates and sets up their Swig wallet
2. Dapp accesses user's wallet to process monthly payments

## Case 1: User Creates Wallet

````rust
use solana_program::pubkey::Pubkey;
use swig_sdk::{SwigWallet, AuthorityManager, AuthorityType, Permission, RecurringConfig};
use solana_sdk::signature::Keypair;

// First, the user creates their wallet
fn setup_user_wallet() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    // Generate a unique wallet ID - save this for later!
    let swig_id = rand::random::<[u8; 32]>();

    // User's wallet and fee payer
    let user_wallet = Keypair::new();
    let fee_payer = Keypair::new();

    // Create the Swig wallet
    let mut wallet = SwigWallet::new(
        swig_id.clone(),
        AuthorityManager::Ed25519(user_wallet.pubkey()),
        &fee_payer,
        &user_wallet,
        "https://api.mainnet-beta.solana.com".to_string(),
    )?;

    // Add NYT (merchant) as authority with recurring payment permission
    let nyt_pubkey = Pubkey::new_unique(); // NYT's public key
    let recurring_config = RecurringConfig::new(30 * 86400)  // Every 30 days

    wallet.add_authority(
        AuthorityType::Ed25519,
        &nyt_pubkey.to_bytes(),
        vec![Permission::Token {
            amount: subscription_cost_per_month,
            recurring: Some(recurring_config),
        }],
    )?;

    println!("Wallet created and NYT authority added!");
    println!("Save this wallet ID: {:?}", swig_id);

    Ok(swig_id)
}

## 🏢 Case 2: Dapp Uses Wallet

```rust
// Later, NYT's backend service processes payments
struct NYTSubscriptionService {
    wallet: SwigWallet<'static>,
}

impl NYTSubscriptionService {
    pub fn new(
        swig_id: [u8; 32],
        merchant: &'static Keypair,
        fee_payer: &'static Keypair,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create wallet instance with same ID but NYT's authority
        let wallet = SwigWallet::new(
            swig_id,
            AuthorityManager::Ed25519(merchant.pubkey()),
            fee_payer,
            merchant,
            "https://api.mainnet-beta.solana.com".to_string(),
        )?;

        Ok(Self { wallet })
    }

    pub fn process_monthly_payment(&mut self) -> Result<(), Box<dyn std::error::Error>> {

        // NYT's payment address
        let nyt_treasury = Pubkey::new_unique();

        // Create transfer instruction
        let payment = system_instruction::transfer(
            &self.wallet.get_swig_account()?,
            &nyt_treasury,
            10_000_000_000, // 10 SOL
        );

        // Sign and send using NYT's authority
        self.wallet.sign(vec![payment], None)?;
        println!("✅ Monthly payment processed!");

        Ok(())
    }
}

// Example usage
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Case 1: User creates wallet and authorizes NYT
    let swig_id = setup_user_wallet()?;
    println!("User wallet setup complete!");

    // Case 2: NYT service processes payment
    let merchant = Keypair::new(); // NYT's keypair
    let fee_payer = Keypair::new();

    let mut nyt_service = NYTSubscriptionService::new(
        swig_id,
        &merchant,
        &fee_payer,
    )?;

    // Process monthly payment
    nyt_service.process_monthly_payment()?;

    Ok(())
}
````

## 📝 What's Happening?

### Case 1: User Setup

1. User generates a unique `swig_id`
2. Creates their Swig wallet
3. Adds NYT as an authority with recurring payment permission
4. Saves the `swig_id` for future reference

### Case 2: Dapp Usage

1. NYT service creates a wallet instance using saved `swig_id`
2. Uses their authority to process monthly payments
3. Transactions are limited by the permissions set in Case 1

## 🔑 Key Points

- Same `swig_id` is used in both cases
- User maintains control through permission settings
- Dapp can only perform authorized actions
- Recurring payments are automatically limited
