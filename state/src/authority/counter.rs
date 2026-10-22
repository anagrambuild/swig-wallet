//! Replay counters shared by roles with the same secp curve and public key.

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
};

use super::{
    secp256k1::{Secp256k1Authority, Secp256k1SessionAuthority},
    secp256r1::{Secp256r1Authority, Secp256r1SessionAuthority},
    AuthorityType,
};
use crate::{
    role::{Position, RoleMut},
    swig::Swig,
    SwigAuthenticateError, Transmutable,
};

// All four secp layouts share the compressed key and counter prefix.
const COUNTER_OFFSET: usize = core::mem::offset_of!(Secp256k1Authority, signature_odometer);
const _: () = {
    assert!(COUNTER_OFFSET == 36);
    assert!(core::mem::offset_of!(Secp256k1Authority, public_key) == 0);
    assert!(core::mem::offset_of!(Secp256k1SessionAuthority, public_key) == 0);
    assert!(core::mem::offset_of!(Secp256r1Authority, public_key) == 0);
    assert!(core::mem::offset_of!(Secp256r1SessionAuthority, public_key) == 0);
    assert!(COUNTER_OFFSET == core::mem::offset_of!(Secp256k1SessionAuthority, signature_odometer));
    assert!(COUNTER_OFFSET == core::mem::offset_of!(Secp256r1Authority, signature_odometer));
    assert!(COUNTER_OFFSET == core::mem::offset_of!(Secp256r1SessionAuthority, signature_odometer));
};

#[derive(Clone, Copy)]
pub struct SecpCounter {
    pub authority_type: AuthorityType,
    pub public_key: [u8; 33],
    pub counter: u32,
}

impl SecpCounter {
    pub fn from_role(role: &RoleMut<'_>) -> Result<Option<Self>, ProgramError> {
        let Some(counter) = role.authority.signature_odometer() else {
            return Ok(None);
        };
        Ok(Some(Self {
            authority_type: role.authority.authority_type(),
            public_key: role
                .authority
                .identity()?
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
            counter,
        }))
    }

    #[inline(always)]
    fn matches_curve(&self, kind: u16) -> bool {
        match self.authority_type {
            AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => kind == 3 || kind == 4,
            AuthorityType::Secp256r1 | AuthorityType::Secp256r1Session => kind == 5 || kind == 6,
            _ => false,
        }
    }

    #[inline(always)]
    fn matches_key(&self, data: &[u8]) -> bool {
        u64::from_le_bytes(data[1..9].try_into().unwrap())
            == u64::from_le_bytes(self.public_key[1..9].try_into().unwrap())
            && data[..33] == self.public_key
    }
}

/// Authenticates against the selected role's counter, then synchronizes same-key roles.
/// Returns the authenticated role and the slot used for its checks.
/// `roles` must contain only roles, excluding the account header and optional tail.
/// Legacy unequal counters align to their previous maximum plus one on first success.
/// That first authentication can accept a replay through a lagging legacy role.
/// On-chain callers must propagate errors so failed transactions roll back all writes.
pub fn authenticate_role<'a>(
    roles: &'a mut [u8],
    role_id: u32,
    accounts: &[AccountInfo],
    authority_payload: &[u8],
    data_payload: &[u8],
    create_session: bool,
) -> Result<Option<(RoleMut<'a>, u64)>, ProgramError> {
    let mut offset = 0;
    let selected = loop {
        if offset == roles.len() {
            return Ok(None);
        }
        let pos_end = offset
            .checked_add(Position::LEN)
            .ok_or(ProgramError::InvalidAccountData)?;
        let bytes = roles
            .get(offset..pos_end)
            .ok_or(ProgramError::InvalidAccountData)?;
        // Position contains only integer fields; do not form a reference at an untrusted boundary.
        let position = unsafe { (bytes.as_ptr() as *const Position).read_unaligned() };
        let boundary = position.boundary() as usize;
        if boundary < pos_end || boundary > roles.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        if position.id() == role_id {
            break offset;
        }
        offset = boundary;
    };
    let slot = Clock::get()?.slot;
    let consumed = {
        let role = Swig::get_mut_role_at(selected, roles)?;
        if create_session && !role.authority.session_based() {
            return Err(SwigAuthenticateError::AuthorityDoesNotSupportSessionBasedAuth.into());
        }
        if role.authority.session_based() && !create_session {
            role.authority
                .authenticate_session(accounts, authority_payload, data_payload, slot)?;
            None
        } else {
            role.authority
                .authenticate(accounts, authority_payload, data_payload, slot)?;
            SecpCounter::from_role(&role)?
        }
    };
    if let Some(counter) = consumed {
        sync_counters(roles, selected, &counter)?;
    }
    Swig::get_mut_role_at(selected, roles).map(|role| Some((role, slot)))
}

/// Writes the shared next counter after authentication succeeds.
fn sync_counters(
    roles: &mut [u8],
    selected: usize,
    counter: &SecpCounter,
) -> Result<(), ProgramError> {
    let mut next = counter.counter;
    let mut previous = next.wrapping_sub(1);
    let mut cursor = 0;
    while cursor < roles.len() {
        let pos_end = cursor + Position::LEN;
        let bytes = roles
            .get(cursor..pos_end)
            .ok_or(ProgramError::InvalidAccountData)?;
        let position = unsafe { (bytes.as_ptr() as *const Position).read_unaligned() };
        let boundary = position.boundary() as usize;
        if boundary < pos_end || boundary > roles.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        if counter.matches_curve(position.authority_type) {
            let len = position.authority_length as usize;
            if len < COUNTER_OFFSET + 4 || pos_end + len > boundary {
                return Err(ProgramError::InvalidAccountData);
            }
            let data = &mut roles[pos_end..pos_end + len];
            if counter.matches_key(data) {
                let stored = u32::from_le_bytes(
                    data[COUNTER_OFFSET..COUNTER_OFFSET + 4].try_into().unwrap(),
                );
                if cursor != selected && stored > previous {
                    // Legacy mismatch: restart once at the group maximum. Earlier writes
                    // used `next <= stored`, so they cannot inflate that maximum.
                    previous = inherited_counter(roles, counter)?;
                    next = previous.wrapping_add(1);
                    cursor = 0;
                    continue;
                }
                data[COUNTER_OFFSET..COUNTER_OFFSET + 4].copy_from_slice(&next.to_le_bytes());
            }
        }
        cursor = boundary;
    }
    Ok(())
}

/// Finds the greatest existing counter for legacy alignment and added/replaced keys.
/// Only existing same-curve full-key matches contribute; unrelated state is untouched.
pub fn inherited_counter(roles: &[u8], authority: &SecpCounter) -> Result<u32, ProgramError> {
    let mut maximum = 0;
    let mut cursor = 0;
    while cursor < roles.len() {
        let pos_end = cursor + Position::LEN;
        let bytes = roles
            .get(cursor..pos_end)
            .ok_or(ProgramError::InvalidAccountData)?;
        // Position contains only integer fields; do not form a reference at an untrusted boundary.
        let position = unsafe { (bytes.as_ptr() as *const Position).read_unaligned() };
        let boundary = position.boundary() as usize;
        if boundary < pos_end || boundary > roles.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        if authority.matches_curve(position.authority_type) {
            let len = position.authority_length as usize;
            if len < COUNTER_OFFSET + 4 || pos_end + len > boundary {
                return Err(ProgramError::InvalidAccountData);
            }
            let data = &roles[pos_end..pos_end + len];
            if authority.matches_key(data) {
                maximum = maximum.max(u32::from_le_bytes(
                    data[COUNTER_OFFSET..COUNTER_OFFSET + 4].try_into().unwrap(),
                ));
            }
        }
        cursor = boundary;
    }
    Ok(maximum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::{all::All, Action, Permission},
        authority::authority_type_to_length,
        swig::SwigBuilder,
        IntoBytes,
    };

    #[repr(C, align(8))]
    struct Buffer([u8; 4096]);

    fn fixture(
        buffer: &mut Buffer,
        entries: &[(AuthorityType, [u8; 33], u32)],
    ) -> (Vec<usize>, usize) {
        let mut offsets = Vec::new();
        let mut at = 0;
        for (id, (kind, key, counter)) in entries.iter().enumerate() {
            let len = authority_type_to_length(kind).unwrap();
            let end = at + Position::LEN + len;
            let b = &mut buffer.0;
            b[at..at + 2].copy_from_slice(&(*kind as u16).to_le_bytes());
            b[at + 2..at + 4].copy_from_slice(&(len as u16).to_le_bytes());
            b[at + 8..at + 12].copy_from_slice(&(id as u32).to_le_bytes());
            b[at + 12..at + 16].copy_from_slice(&(end as u32).to_le_bytes());
            let key_len = if *kind == AuthorityType::Ed25519 {
                32
            } else {
                33
            };
            b[at + 16..at + 16 + key_len].copy_from_slice(&key[..key_len]);
            if matches!(
                kind,
                AuthorityType::Secp256k1
                    | AuthorityType::Secp256k1Session
                    | AuthorityType::Secp256r1
                    | AuthorityType::Secp256r1Session
            ) {
                b[at + 52..at + 56].copy_from_slice(&counter.to_le_bytes());
            }
            offsets.push(at);
            at = end;
        }
        (offsets, at)
    }
    fn counter(b: &Buffer, offset: usize) -> u32 {
        u32::from_le_bytes(b.0[offset + 52..offset + 56].try_into().unwrap())
    }

    #[test]
    fn synchronizes_full_key_peers_across_plain_and_session_types_only() {
        for (kind, session, other_curve) in [
            (
                AuthorityType::Secp256k1,
                AuthorityType::Secp256k1Session,
                AuthorityType::Secp256r1,
            ),
            (
                AuthorityType::Secp256r1,
                AuthorityType::Secp256r1Session,
                AuthorityType::Secp256k1,
            ),
        ] {
            let key = [7; 33];
            let mut different = key;
            different[32] ^= 1; // Same eight-byte precheck.
            let mut opposite = key;
            opposite[0] ^= 1; // Same x-coordinate, opposite point.
            let mut b = Buffer([0; 4096]);
            let (offsets, end) = fixture(
                &mut b,
                &[
                    (kind, key, 18),
                    (session, key, 27),
                    (kind, different, 100),
                    (other_curve, key, 100),
                    (AuthorityType::Ed25519, key, 0),
                    (kind, opposite, 100),
                ],
            );
            let before = b.0;
            let shared = SecpCounter {
                authority_type: kind,
                public_key: key,
                counter: 18,
            };
            sync_counters(&mut b.0[..end], offsets[0], &shared).unwrap();
            let mut expected = before;
            for at in &offsets[..2] {
                expected[at + 52..at + 56].copy_from_slice(&28u32.to_le_bytes());
            }
            assert_eq!(b.0, expected);
        }
    }

    #[test]
    fn legacy_maximum_can_be_first_middle_or_last_and_next_use_advances_once() {
        for kind in [AuthorityType::Secp256k1, AuthorityType::Secp256r1] {
            for counters in [[100, 27, 30], [27, 100, 30], [27, 30, 100], [27, 28, 27]] {
                for selected in 0..3 {
                    let mut b = Buffer([0; 4096]);
                    let (offsets, end) =
                        fixture(&mut b, &counters.map(|counter| (kind, [9; 33], counter)));
                    let next = counters.iter().max().unwrap() + 1;
                    for expected in [next, next + 1] {
                        // Existing authority verification increments only the selected role.
                        let consumed = counter(&b, offsets[selected]).wrapping_add(1);
                        b.0[offsets[selected] + 52..offsets[selected] + 56]
                            .copy_from_slice(&consumed.to_le_bytes());
                        let shared = SecpCounter {
                            authority_type: kind,
                            public_key: [9; 33],
                            counter: consumed,
                        };
                        sync_counters(&mut b.0[..end], offsets[selected], &shared).unwrap();
                        for at in &offsets {
                            assert_eq!(counter(&b, *at), expected);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn preserves_the_existing_full_width_counter_wrap() {
        let mut b = Buffer([0; 4096]);
        let key = [9; 33];
        for counters in [[u32::MAX, u32::MAX], [27, u32::MAX]] {
            let (offsets, end) = fixture(
                &mut b,
                &[
                    (AuthorityType::Secp256k1, key, counters[0]),
                    (AuthorityType::Secp256k1Session, key, counters[1]),
                ],
            );
            for expected in [0, 1] {
                let consumed = counter(&b, offsets[0]).wrapping_add(1);
                b.0[offsets[0] + 52..offsets[0] + 56].copy_from_slice(&consumed.to_le_bytes());
                let shared = SecpCounter {
                    authority_type: AuthorityType::Secp256k1,
                    public_key: key,
                    counter: consumed,
                };
                sync_counters(&mut b.0[..end], offsets[0], &shared).unwrap();
                for at in &offsets {
                    assert_eq!(counter(&b, *at), expected);
                }
            }
        }
    }

    #[test]
    fn inherits_highest_counter_only_from_matching_curve_and_entire_key() {
        let mut b = Buffer([0; 4096]);
        let key = [11; 33];
        let mut other = key;
        other[32] = 12;
        let (_, end) = fixture(
            &mut b,
            &[
                (AuthorityType::Secp256k1, key, 5),
                (AuthorityType::Secp256k1Session, key, 9),
                (AuthorityType::Secp256r1, key, 100),
                (AuthorityType::Secp256k1, other, 200),
            ],
        );
        let identity = SecpCounter {
            authority_type: AuthorityType::Secp256k1,
            public_key: key,
            counter: 0,
        };
        assert_eq!(inherited_counter(&b.0[..end], &identity).unwrap(), 9);
        assert_eq!(inherited_counter(&[], &identity).unwrap(), 0);
    }

    #[test]
    fn maximum_scan_rejects_malformed_peers_without_writing() {
        let key = [11; 33];
        let kind = AuthorityType::Secp256k1;
        let identity = SecpCounter {
            authority_type: kind,
            public_key: key,
            counter: 18,
        };
        for malformed in 0..3 {
            let mut b = Buffer([0; 4096]);
            let (offsets, end) = fixture(&mut b, &[(kind, key, 17); 3]);
            b.0[offsets[malformed] + 2..offsets[malformed] + 4]
                .copy_from_slice(&32u16.to_le_bytes());
            let before = b.0;
            assert_eq!(
                inherited_counter(&b.0[..end], &identity),
                Err(ProgramError::InvalidAccountData)
            );
            assert_eq!(b.0, before);
        }
        let mut b = Buffer([0; 4096]);
        fixture(&mut b, &[(kind, key, 17)]);
        assert_eq!(
            inherited_counter(&b.0[..55], &identity),
            Err(ProgramError::InvalidAccountData)
        );
    }

    #[test]
    fn lookup_never_interprets_tail_bytes_as_another_role() {
        let mut b = Buffer([0; 4096]);
        let key = [11; 33];
        fixture(
            &mut b,
            &[
                (AuthorityType::Secp256k1, key, 17),
                (AuthorityType::Secp256k1, key, 17),
            ],
        );
        // The canonical account split supplies only the first role.
        assert!(authenticate_role(&mut b.0[..56], 1, &[], &[], &[], false)
            .unwrap()
            .is_none());
    }

    #[test]
    fn selected_role_rejects_invalid_layout_before_forming_authority_references() {
        let mut b = Buffer([0; 4096]);
        fixture(&mut b, &[(AuthorityType::Secp256k1, [11; 33], 17)]);
        assert!(matches!(
            Swig::get_mut_role_at(1, &mut b.0),
            Err(ProgramError::InvalidAccountData)
        ));
        b.0[2..4].copy_from_slice(&32u16.to_le_bytes());
        assert!(matches!(
            Swig::get_mut_role_at(0, &mut b.0),
            Err(ProgramError::InvalidAccountData)
        ));
        b.0[2..4].copy_from_slice(&40u16.to_le_bytes());
        b.0[12..16].copy_from_slice(&40u32.to_le_bytes());
        assert!(matches!(
            Swig::get_mut_role_at(0, &mut b.0),
            Err(ProgramError::InvalidAccountData)
        ));
    }

    #[test]
    fn builder_initializes_a_duplicate_from_an_existing_counter() {
        let key: [u8; 33] =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap();
        let mut b = Buffer([0; 4096]);
        let action = Action::new(
            Permission::All,
            All::LEN as u16,
            (Action::LEN + All::LEN) as u32,
        );
        let mut actions = action.into_bytes().unwrap().to_vec();
        actions.extend_from_slice(All.into_bytes().unwrap());
        let mut builder = SwigBuilder::create(&mut b.0, Swig::new([1; 32], 255, 254)).unwrap();
        builder
            .add_role(AuthorityType::Secp256k1, &key, &actions)
            .unwrap();
        builder.role_buffer[52..56].copy_from_slice(&37u32.to_le_bytes());
        builder
            .add_role(AuthorityType::Secp256k1, &key, &actions)
            .unwrap();
        let role = Swig::get_mut_role(1, builder.role_buffer).unwrap().unwrap();
        assert_eq!(role.authority.signature_odometer(), Some(37));
    }
}
