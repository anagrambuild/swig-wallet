use core::mem::MaybeUninit;

use pinocchio::entrypoint::deserialize;
use swig_state::IntoBytes;

use super::*;

const TIERS: [DeveloperTier; 4] = [
    DeveloperTier::Free,
    DeveloperTier::Pro,
    DeveloperTier::Ultra,
    DeveloperTier::Enterprise,
];
const SIGNER: Pubkey = [9; 32];
const VALID_UNTIL: i64 = 1_000;

fn account(tier: DeveloperTier, signer: Pubkey) -> DeveloperAccount {
    let mut account = DeveloperAccount::new(254, [7; 32], tier, VALID_UNTIL);
    account.signer = signer;
    account
}

fn check(
    account: &DeveloperAccount,
    signer_key: &Pubkey,
    signed: bool,
    unix_timestamp: i64,
) -> Result<(), u32> {
    check_developer_sponsorship(
        account,
        signer_key,
        signed,
        DeveloperTier::Pro,
        unix_timestamp,
    )
    .map_err(|error| error as u32)
}

struct TestAccount {
    owner: Pubkey,
    writable: bool,
    data: Vec<u8>,
}

fn developer_account_data() -> Vec<u8> {
    account(DeveloperTier::Pro, SIGNER)
        .into_bytes()
        .unwrap()
        .to_vec()
}

fn registry_account(data: Vec<u8>) -> TestAccount {
    TestAccount {
        owner: developer_account_registry_state::ID,
        writable: false,
        data,
    }
}

fn signer_account() -> TestAccount {
    TestAccount {
        owner: [0; 32],
        writable: false,
        data: Vec::new(),
    }
}

// Lays out both accounts in the runtime's input format, so every rejection
// returns before `verify_pda`, which only runs on-chain.
fn validate(developer_account: TestAccount, developer_signer: TestAccount) -> Result<(), u32> {
    let states = [(&developer_account, [1; 32]), (&developer_signer, SIGNER)];
    let mut backing = vec![0u64; 4_000];
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), backing.len() * 8)
    };
    bytes[..8].copy_from_slice(&(states.len() as u64).to_le_bytes());
    let mut offset = 8;
    for (state, key) in states {
        bytes[offset] = u8::MAX;
        bytes[offset + 1] = 1;
        bytes[offset + 2] = u8::from(state.writable);
        bytes[offset + 8..offset + 40].copy_from_slice(&key);
        bytes[offset + 40..offset + 72].copy_from_slice(&state.owner);
        bytes[offset + 80..offset + 88].copy_from_slice(&(state.data.len() as u64).to_le_bytes());
        bytes[offset + 88..offset + 88 + state.data.len()].copy_from_slice(&state.data);
        offset = (offset + 88 + state.data.len() + 10_240 + 8).next_multiple_of(8);
    }
    let mut accounts = [const { MaybeUninit::<AccountInfo>::uninit() }; 2];
    let (_, count, _) = unsafe { deserialize(bytes.as_mut_ptr(), &mut accounts) };
    assert_eq!(count, 2);
    let [developer_account, developer_signer] =
        unsafe { accounts.map(|account| account.assume_init()) };

    validate_developer_account(&developer_account, &developer_signer, DeveloperTier::Pro, 0)
        .map_err(|error| error as u32)
}

#[test]
fn validation_rejects_a_writable_developer_account() {
    let mut developer_account = registry_account(developer_account_data());
    developer_account.writable = true;
    assert_eq!(
        validate(developer_account, signer_account()),
        Err(SwigError::WritableDeveloperProofAccount as u32)
    );
}

#[test]
fn validation_rejects_a_writable_developer_signer() {
    let mut developer_signer = signer_account();
    developer_signer.writable = true;
    assert_eq!(
        validate(registry_account(developer_account_data()), developer_signer),
        Err(SwigError::WritableDeveloperProofAccount as u32)
    );
}

#[test]
fn validation_rejects_an_account_not_owned_by_the_registry() {
    let mut developer_account = registry_account(developer_account_data());
    developer_account.owner = [3; 32];
    assert_eq!(
        validate(developer_account, signer_account()),
        Err(SwigError::InvalidDeveloperAccount as u32)
    );
}

#[test]
fn validation_rejects_malformed_account_data() {
    let mut truncated = developer_account_data();
    truncated.pop();
    let mut wrong_discriminator = developer_account_data();
    wrong_discriminator[0] = 2;
    for data in [Vec::new(), truncated, wrong_discriminator] {
        assert_eq!(
            validate(registry_account(data), signer_account()),
            Err(SwigError::InvalidDeveloperAccount as u32)
        );
    }
}

#[test]
fn sponsorship_passes_for_a_live_account_at_or_above_the_tier() {
    for tier in [
        DeveloperTier::Pro,
        DeveloperTier::Ultra,
        DeveloperTier::Enterprise,
    ] {
        assert_eq!(
            check(&account(tier, SIGNER), &SIGNER, true, VALID_UNTIL - 1),
            Ok(())
        );
    }
}

#[test]
fn sponsorship_rejects_an_account_at_or_after_valid_until() {
    let account = account(DeveloperTier::Pro, SIGNER);
    let expired = Err(SwigError::DeveloperAccountExpired as u32);
    assert_eq!(check(&account, &SIGNER, true, VALID_UNTIL), expired);
    assert_eq!(check(&account, &SIGNER, true, VALID_UNTIL + 1), expired);
    assert_eq!(check(&account, &SIGNER, true, i64::MAX), expired);
}

#[test]
fn sponsorship_passes_exactly_when_the_tier_meets_the_requirement() {
    for tier in TIERS {
        for required_tier in TIERS {
            let result = check_developer_sponsorship(
                &account(tier, SIGNER),
                &SIGNER,
                true,
                required_tier,
                0,
            )
            .map_err(|error| error as u32);
            let expected = if tier >= required_tier {
                Ok(())
            } else {
                Err(SwigError::InsufficientDeveloperTier as u32)
            };
            assert_eq!(
                result, expected,
                "tier {tier:?}, required {required_tier:?}"
            );
        }
    }
}

#[test]
fn sponsorship_rejects_an_unknown_tier() {
    let mut account = account(DeveloperTier::Pro, SIGNER);
    account.tier = 9;
    assert_eq!(
        check(&account, &SIGNER, true, 0),
        Err(SwigError::InvalidDeveloperAccount as u32)
    );
}

#[test]
fn sponsorship_rejects_an_unset_signer() {
    assert_eq!(
        check(&account(DeveloperTier::Pro, [0; 32]), &[0; 32], true, 0),
        Err(SwigError::DeveloperSignerNotSet as u32)
    );
}

#[test]
fn sponsorship_rejects_a_different_signer_key() {
    assert_eq!(
        check(&account(DeveloperTier::Pro, SIGNER), &[8; 32], true, 0),
        Err(SwigError::DeveloperSignerMismatch as u32)
    );
}

#[test]
fn sponsorship_rejects_a_matching_signer_that_did_not_sign() {
    assert_eq!(
        check(&account(DeveloperTier::Pro, SIGNER), &SIGNER, false, 0),
        Err(SwigError::MissingDeveloperSignature as u32)
    );
}

#[test]
fn sponsorship_checks_run_in_order() {
    let expired_free_unset = account(DeveloperTier::Free, [0; 32]);
    assert_eq!(
        check(&expired_free_unset, &[8; 32], false, VALID_UNTIL),
        Err(SwigError::DeveloperAccountExpired as u32)
    );
    assert_eq!(
        check(&expired_free_unset, &[8; 32], false, 0),
        Err(SwigError::InsufficientDeveloperTier as u32)
    );
    let unset = account(DeveloperTier::Pro, [0; 32]);
    assert_eq!(
        check(&unset, &[8; 32], false, 0),
        Err(SwigError::DeveloperSignerNotSet as u32)
    );
    assert_eq!(
        check(&account(DeveloperTier::Pro, SIGNER), &[8; 32], false, 0),
        Err(SwigError::DeveloperSignerMismatch as u32)
    );
}

#[test]
fn only_token_limit_is_premium() {
    let mut value = 0;
    while let Ok(permission) = Permission::try_from(value) {
        let expected = (permission == Permission::TokenLimit).then_some(DeveloperTier::Pro);
        assert_eq!(
            required_developer_tier(permission),
            expected,
            "{permission:?}"
        );
        value += 1;
    }
}

#[test]
fn developer_account_error_codes_are_stable() {
    assert_eq!(SwigError::PayerMustBeWritableSigner as u32, 79);
    assert_eq!(SwigError::WritableDeveloperProofAccount as u32, 80);
    assert_eq!(SwigError::InvalidDeveloperAccount as u32, 81);
    assert_eq!(SwigError::DeveloperAccountExpired as u32, 82);
    assert_eq!(SwigError::InsufficientDeveloperTier as u32, 83);
    assert_eq!(SwigError::DeveloperSignerNotSet as u32, 84);
    assert_eq!(SwigError::DeveloperSignerMismatch as u32, 85);
    assert_eq!(SwigError::MissingDeveloperSignature as u32, 86);
    assert_eq!(SwigError::MissingDeveloperProofAccounts as u32, 87);
}
