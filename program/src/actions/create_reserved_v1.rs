use pinocchio::{
    account_info::AccountInfo,
    instruction::Seed,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, Transfer};
use swig_assertions::{
    check_system_owner, check_writable, check_writable_signer, check_zero_data, find_self_pda,
};
use swig_state::{
    action::{Action, Permission},
    authority::authority_type_to_length,
    reservation::{validate_package, DOMAIN, HEADER_LEN},
    role::Position,
    swig::{swig_wallet_address_seeds, Swig, SwigBuilder},
    tail, Discriminator, IntoBytes, Transmutable,
};

use crate::{
    error::SwigError,
    instruction::accounts::{Context, CreateReservedV1Accounts},
};

pub fn create_reserved_v1(ctx: Context<CreateReservedV1Accounts>, data: &[u8]) -> ProgramResult {
    validate_accounts(&ctx.accounts)?;
    let package = data.get(2..).ok_or(ProgramError::InvalidInstructionData)?;
    let initial_authority_type = validate_package(package, &crate::ID)?;
    let (reservation_header, initial_authority) = package.split_at(HEADER_LEN);

    // The header contains the version, program ID, salt, and authority type.
    // Hashing it with the initial public key binds this address to the same
    // authority installed as role zero below.
    let commitment =
        solana_sha256_hasher::hashv(&[DOMAIN, reservation_header, initial_authority]).to_bytes();
    let config = ctx.accounts.swig;
    let bump = find_self_pda(
        &[DOMAIN, &commitment],
        config.key(),
        SwigError::InvalidSeedSwigAccount,
    )?;
    let wallet_bump = find_self_pda(
        &swig_wallet_address_seeds(config.key()),
        ctx.accounts.swig_wallet_address.key(),
        SwigError::InvalidSeedSwigAccount,
    )?;
    let state = Swig::new(commitment, bump, wallet_bump);
    validate_config(config, &state)?;
    if config.is_owned_by(&crate::ID) {
        // Validation confirmed this is the same active reservation. Treat retries
        // as successful without resetting its authorities, counters, or other state.
        return Ok(());
    }

    let all = Action::new(Permission::All, 0, Action::LEN as u32);
    let actions = all.into_bytes()?;
    let account_size = Swig::LEN
        + Position::LEN
        + authority_type_to_length(&initial_authority_type)?
        + Action::LEN;
    initialize_accounts(&ctx.accounts, &state, account_size)?;

    let mut bytes = config.try_borrow_mut_data()?;
    SwigBuilder::create(&mut bytes, state)?.add_role(
        initial_authority_type,
        initial_authority,
        actions,
    )
}

fn validate_accounts(accounts: &CreateReservedV1Accounts) -> ProgramResult {
    let config = accounts.swig;
    let payer = accounts.payer;
    let wallet = accounts.swig_wallet_address;
    let system = accounts.system_program;
    check_writable_signer(payer, SwigError::PayerMustBeWritableSigner)?;
    check_writable(config, ProgramError::InvalidAccountData)?;
    check_writable(wallet, ProgramError::InvalidAccountData)?;
    if system.key() != &pinocchio_system::ID || !system.executable() {
        return Err(SwigError::InvalidSystemProgram.into());
    }
    if config.key() == wallet.key()
        || config.key() == payer.key()
        || wallet.key() == payer.key()
        || config.executable()
        || wallet.executable()
        || payer.executable()
    {
        return Err(ProgramError::InvalidArgument);
    }
    check_system_owner(payer, ProgramError::IllegalOwner)?;
    check_zero_data(payer, ProgramError::InvalidAccountData)?;
    check_system_owner(wallet, SwigError::OwnerMismatchSwigAccount)?;
    check_zero_data(wallet, SwigError::AccountNotEmptySwigAccount)?;

    Ok(())
}

fn validate_config(config: &AccountInfo, state: &Swig) -> ProgramResult {
    // The config PDA and immutable commitment identify this reservation even
    // after role zero rotates. Retrying never resets roles, counters, or tails.
    // Closed accounts retain program ownership and discriminator 255 forever.
    if config.is_owned_by(&crate::ID) {
        let bytes = config.try_borrow_data()?;
        if bytes.first() != Some(&(Discriminator::SwigConfigAccount as u8)) {
            return Err(SwigError::InvalidSwigAccountDiscriminator.into());
        }
        let parts = Swig::split_parts(&bytes)?;
        tail::validate_strict(parts.tail)?;
        if parts.state.id != state.id
            || parts.state.bump != state.bump
            || parts.state.wallet_bump != state.wallet_bump
            || parts.state._padding != [0; 3]
        {
            return Err(ProgramError::InvalidAccountData);
        }
    } else {
        check_system_owner(config, SwigError::OwnerMismatchSwigAccount)?;
        check_zero_data(config, SwigError::AccountNotEmptySwigAccount)?;
    }

    Ok(())
}

fn initialize_accounts(
    accounts: &CreateReservedV1Accounts,
    state: &Swig,
    account_size: usize,
) -> ProgramResult {
    let config = accounts.swig;
    let payer = accounts.payer;
    let wallet = accounts.swig_wallet_address;
    let rent = Rent::get()?;
    let config_top_up = rent
        .minimum_balance(account_size)
        .saturating_sub(config.lamports());
    let wallet_top_up = rent.minimum_balance(0).saturating_sub(wallet.lamports());
    if payer.lamports()
        < config_top_up
            .checked_add(wallet_top_up)
            .ok_or(ProgramError::ArithmeticOverflow)?
    {
        return Err(ProgramError::InsufficientFunds);
    }

    // All caller-controlled input is checked before funding, allocating or
    // assigning. Top-ups preserve deposits sent to either PDA before activation.
    if config_top_up > 0 {
        Transfer {
            from: payer,
            to: config,
            lamports: config_top_up,
        }
        .invoke()?;
    }
    let bump_seed = [state.bump];
    let seeds = [
        Seed::from(DOMAIN),
        Seed::from(&state.id),
        Seed::from(&bump_seed),
    ];
    let signers = [seeds.as_slice().into()];
    Allocate {
        account: config,
        space: account_size as u64,
    }
    .invoke_signed(&signers)?;
    Assign {
        account: config,
        owner: &crate::ID,
    }
    .invoke_signed(&signers)?;
    if wallet_top_up > 0 {
        Transfer {
            from: payer,
            to: wallet,
            lamports: wallet_top_up,
        }
        .invoke()?;
    }
    Ok(())
}
