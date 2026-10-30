use swig_state::tail::{
    active_sub_account_count, authorization_locks::*, rent_claimer, validate_strict,
};

fn lock(lock_id: u32, role_id: u32, expiry_slot: u64) -> AuthorizationLock {
    AuthorizationLock {
        asset_account: [lock_id as u8 + 1; 32],
        mint: NATIVE_SOL_MINT,
        amount: 1_000 + lock_id as u64,
        expiry_slot,
        role_id,
        lock_id,
    }
}

#[test]
fn lock_round_trips() {
    let original = AuthorizationLock {
        asset_account: [3; 32],
        mint: [4; 32],
        amount: u64::MAX,
        expiry_slot: 99,
        role_id: 7,
        lock_id: 11,
    };
    let bytes = original.to_bytes();
    assert_eq!(AuthorizationLock::from_bytes(&bytes).unwrap(), original);
    assert!(AuthorizationLock::from_bytes(&bytes[..LOCK_LEN - 1]).is_err());
}

#[test]
fn entry_round_trips_through_read() {
    let locks = [lock(0, 1, 50), lock(1, 2, 60)];
    let tail = entry(2, &locks).unwrap();
    validate_strict(&tail).unwrap();
    let parsed = read(&tail).unwrap().unwrap();
    assert_eq!(parsed.next_lock_id(), 2);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed.iter().collect::<Vec<_>>(), locks.to_vec());
    assert_eq!(parsed.get(1), Some(locks[1]));
    assert_eq!(parsed.get(2), None);
}

#[test]
fn empty_entry_is_valid_and_keeps_counter() {
    let tail = entry(9, &[]).unwrap();
    validate_strict(&tail).unwrap();
    let parsed = read(&tail).unwrap().unwrap();
    assert!(parsed.is_empty());
    assert_eq!(parsed.next_lock_id(), 9);
}

#[test]
fn activity_is_exclusive_of_expiry_slot() {
    let l = lock(0, 0, 100);
    assert!(l.is_active(99));
    assert!(!l.is_active(100));
    assert!(!l.is_active(101));
}

#[test]
fn helpers_ignore_expired_locks() {
    let locks = [lock(0, 1, 50), lock(1, 2, 200)];
    let tail = entry(2, &locks).unwrap();
    assert!(!role_has_active_locks(&tail, 1, 50).unwrap());
    assert!(role_has_active_locks(&tail, 1, 49).unwrap());
    assert!(role_has_active_locks(&tail, 2, 100).unwrap());
    assert!(has_active_locks(&tail, 100).unwrap());
    assert!(!has_active_locks(&tail, 200).unwrap());
    assert!(account_has_active_locks(&tail, &locks[1].asset_account, 100).unwrap());
    assert!(!account_has_active_locks(&tail, &locks[0].asset_account, 100).unwrap());
    assert!(!has_active_locks(&[], 0).unwrap());
}

#[test]
fn validate_rejects_bad_entries() {
    // Wrong version.
    let mut tail = entry(1, &[lock(0, 0, 10)]).unwrap();
    tail[1] = VERSION + 1;
    assert!(validate_strict(&tail).is_err());

    // Lock id not below the counter.
    let tail = entry(0, &[lock(0, 0, 10)]).unwrap();
    assert!(validate_strict(&tail).is_err());

    // Duplicate lock id.
    let tail = entry(5, &[lock(1, 0, 10), lock(1, 0, 20)]).unwrap();
    assert!(validate_strict(&tail).is_err());

    // Out-of-order ids.
    let tail = entry(5, &[lock(2, 0, 10), lock(1, 0, 20)]).unwrap();
    assert!(validate_strict(&tail).is_err());
    let tail = entry(5, &[lock(1, 0, 10), lock(3, 0, 20)]).unwrap();
    assert!(validate_strict(&tail).is_ok());

    // Zero amount.
    let mut zero = lock(0, 0, 10);
    zero.amount = 0;
    assert!(validate_strict(&entry(1, &[zero]).unwrap()).is_err());

    // Value not a multiple of the record size.
    let mut tail = entry(1, &[lock(0, 0, 10)]).unwrap();
    tail.pop();
    tail[2..4].copy_from_slice(&((LOCK_LEN - 1) as u16).to_le_bytes());
    assert!(validate_strict(&tail).is_err());

    // Two lock entries.
    let mut tail = entry(1, &[lock(0, 0, 10)]).unwrap();
    tail.extend_from_slice(&entry(1, &[]).unwrap());
    assert!(validate_strict(&tail).is_err());
}

#[test]
fn entry_rejects_too_many_locks() {
    let locks: Vec<_> = (0..=MAX_AUTHORIZATION_LOCKS as u32)
        .map(|id| lock(id, 0, 10))
        .collect();
    assert!(entry(100, &locks).is_err());
    assert!(entry(100, &locks[..MAX_AUTHORIZATION_LOCKS]).is_ok());
}

#[test]
fn rebuild_preserves_other_entries_in_place() {
    let rent = rent_claimer::entry(&[7u8; 32]);
    let count = active_sub_account_count::entry(3);
    let locks_v1 = entry(1, &[lock(0, 0, 10)]).unwrap();
    let tail = [rent.as_slice(), locks_v1.as_slice(), count.as_slice()].concat();
    validate_strict(&tail).unwrap();

    let new_locks = [lock(0, 0, 10), lock(1, 2, 20)];
    let rebuilt = rebuild_tail(&tail, 2, &new_locks).unwrap();
    validate_strict(&rebuilt).unwrap();
    let expected = [
        rent.as_slice(),
        entry(2, &new_locks).unwrap().as_slice(),
        count.as_slice(),
    ]
    .concat();
    assert_eq!(rebuilt, expected);
    assert_eq!(rent_claimer::read(&rebuilt).unwrap(), Some(&[7u8; 32]));
    assert_eq!(active_sub_account_count::read(&rebuilt).unwrap(), Some(3));
}

#[test]
fn rebuild_appends_when_missing() {
    let rent = rent_claimer::entry(&[1u8; 32]);
    let rebuilt = rebuild_tail(&rent, 1, &[lock(0, 0, 10)]).unwrap();
    assert_eq!(&rebuilt[..rent.len()], rent.as_slice());
    assert_eq!(read_strict(&rebuilt).unwrap().unwrap().len(), 1);

    let rebuilt = rebuild_tail(&[], 1, &[lock(0, 0, 10)]).unwrap();
    assert_eq!(read_strict(&rebuilt).unwrap().unwrap().len(), 1);
}
