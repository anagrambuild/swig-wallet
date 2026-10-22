//! Replay counters shared by roles with the same secp curve and public key.

use pinocchio::{account_info::AccountInfo, program_error::ProgramError};

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

/// Authenticates once, then consumes the counter across all same-key roles.
/// `role_count` bounds a roles-plus-tail slice; `None` requires a roles-only slice.
/// On-chain callers must propagate errors so transaction rollback also restores
/// earlier counter writes. Session-key authentication does not consume a root counter.
#[allow(clippy::too_many_arguments)]
pub fn authenticate_role<'a>(
    roles: &'a mut [u8],
    role_count: Option<u16>,
    role_id: u32,
    accounts: &[AccountInfo],
    authority_payload: &[u8],
    data_payload: &[u8],
    slot: u64,
    create_session: bool,
) -> Result<Option<RoleMut<'a>>, ProgramError> {
    let mut offset = 0;
    let mut remaining = role_count.map(usize::from).unwrap_or(usize::MAX);
    let selected = loop {
        if remaining == 0 || offset == roles.len() {
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
        remaining -= 1;
    };
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
    let end = if let Some(counter) = consumed {
        advance_counters(roles, role_count, selected, &counter)?
    } else if let Some(count) = role_count {
        // The hot path uses this walk in place of split_parts_mut's role walk.
        roles_end(roles, count)?
    } else {
        roles.len()
    };
    Swig::get_mut_role_at(selected, &mut roles[..end]).map(Some)
}

fn roles_end(roles: &[u8], count: u16) -> Result<usize, ProgramError> {
    let mut cursor = 0;
    for _ in 0..count {
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
        cursor = boundary;
    }
    Ok(cursor)
}

/// Advances peers only after the selected authority has verified and stored its
/// next counter. A legacy peer ahead of the selected role rejects the transaction;
/// first use through a role at the group maximum safely aligns lower peers.
pub fn advance_counters(
    roles: &mut [u8],
    count: Option<u16>,
    selected: usize,
    consumed: &SecpCounter,
) -> Result<usize, ProgramError> {
    match count {
        Some(count) => advance_counters_inner::<true>(roles, count, selected, consumed),
        None => advance_counters_inner::<false>(roles, 0, selected, consumed),
    }
}

// The counted SignV2 path replaces its full role walk. Other callers already
// hold a validated roles-only slice. Specializing the bound avoids testing both
// termination conditions on every role.
#[inline(never)]
fn advance_counters_inner<const COUNTED: bool>(
    roles: &mut [u8],
    count: u16,
    selected: usize,
    consumed: &SecpCounter,
) -> Result<usize, ProgramError> {
    let previous = consumed.counter.wrapping_sub(1);
    let curve = match consumed.authority_type {
        AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => 3u16,
        AuthorityType::Secp256r1 | AuthorityType::Secp256r1Session => 5u16,
        _ => return Err(ProgramError::InvalidAccountData),
    };
    let prefix = u64::from_le_bytes(consumed.public_key[1..9].try_into().unwrap());
    let mut cursor = 0;
    let mut remaining = count;
    while if COUNTED {
        remaining != 0
    } else {
        cursor < roles.len()
    } {
        let pos_end = cursor + Position::LEN;
        if pos_end > roles.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        let position =
            unsafe { (roles[cursor..pos_end].as_ptr() as *const Position).read_unaligned() };
        let boundary = position.boundary() as usize;
        if boundary < pos_end || boundary > roles.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        if position.authority_type.wrapping_sub(curve) <= 1 {
            if position.authority_length < 40 || pos_end + 40 > boundary {
                return Err(ProgramError::InvalidAccountData);
            }
            if u64::from_le_bytes(roles[pos_end + 1..pos_end + 9].try_into().unwrap()) == prefix
                && roles[pos_end..pos_end + 33] == consumed.public_key
                && cursor != selected
            {
                let stored =
                    u32::from_le_bytes(roles[pos_end + 36..pos_end + 40].try_into().unwrap());
                if stored > previous {
                    return Err(SwigAuthenticateError::PermissionDeniedSecpCounterBehind.into());
                }
                roles[pos_end + 36..pos_end + 40].copy_from_slice(&consumed.counter.to_le_bytes());
            }
        }
        cursor = boundary;
        if COUNTED {
            remaining -= 1;
        }
    }
    Ok(cursor)
}

/// Initializes an added/replaced duplicate from the greatest existing counter.
/// Only existing same-curve full-key matches contribute; unrelated state is untouched.
pub fn inherited_counter(
    roles: &[u8],
    count: u16,
    authority: &SecpCounter,
) -> Result<u32, ProgramError> {
    let mut maximum = 0;
    let mut cursor = 0;
    for _ in 0..count {
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

    fn fixture(buffer: &mut Buffer, entries: &[(AuthorityType, [u8; 33], u32)]) -> Vec<usize> {
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
        offsets
    }
    fn counter(b: &Buffer, offset: usize) -> u32 {
        u32::from_le_bytes(b.0[offset + 52..offset + 56].try_into().unwrap())
    }

    #[test]
    fn advances_full_key_peers_across_plain_and_session_types_only() {
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
            let offsets = fixture(
                &mut b,
                &[
                    (kind, key, 18),
                    (session, key, 17),
                    (kind, different, 17),
                    (other_curve, key, 17),
                    (AuthorityType::Ed25519, key, 0),
                    (kind, opposite, 17),
                ],
            );
            let before = b.0;
            advance_counters(
                &mut b.0,
                Some(6),
                0,
                &SecpCounter {
                    authority_type: kind,
                    public_key: key,
                    counter: 18,
                },
            )
            .unwrap();
            let mut expected = before;
            expected[offsets[1] + 52..offsets[1] + 56].copy_from_slice(&18u32.to_le_bytes());
            assert_eq!(b.0, expected);
        }
    }

    #[test]
    fn highest_existing_counter_aligns_lower_peers() {
        for kind in [AuthorityType::Secp256k1, AuthorityType::Secp256r1] {
            let mut b = Buffer([0; 4096]);
            let key = [9; 33];
            let offsets = fixture(&mut b, &[(kind, key, 5), (kind, key, 10), (kind, key, 7)]);
            advance_counters(
                &mut b.0,
                Some(3),
                offsets[1],
                &SecpCounter {
                    authority_type: kind,
                    public_key: key,
                    counter: 10,
                },
            )
            .unwrap();
            for offset in offsets {
                assert_eq!(counter(&b, offset), 10);
            }
        }
    }

    #[test]
    fn a_counter_consumed_by_a_peer_cannot_execute_through_a_lagging_role() {
        let mut b = Buffer([0; 4096]);
        let key = [9; 33];
        fixture(
            &mut b,
            &[
                (AuthorityType::Secp256k1, key, 6),
                (AuthorityType::Secp256k1, key, 9),
            ],
        );
        let before = b.0;
        assert_eq!(
            advance_counters(
                &mut b.0,
                Some(2),
                0,
                &SecpCounter {
                    authority_type: AuthorityType::Secp256k1,
                    public_key: key,
                    counter: 6
                }
            ),
            Err(SwigAuthenticateError::PermissionDeniedSecpCounterBehind.into())
        );
        assert_eq!(b.0, before);
    }

    #[test]
    fn preserves_the_existing_full_width_counter_wrap() {
        let mut b = Buffer([0; 4096]);
        let key = [9; 33];
        let offsets = fixture(
            &mut b,
            &[
                (AuthorityType::Secp256k1, key, 0),
                (AuthorityType::Secp256k1Session, key, u32::MAX),
            ],
        );
        advance_counters(
            &mut b.0,
            Some(2),
            0,
            &SecpCounter {
                authority_type: AuthorityType::Secp256k1,
                public_key: key,
                counter: 0,
            },
        )
        .unwrap();
        assert_eq!(counter(&b, offsets[1]), 0);
    }

    #[test]
    fn inherits_highest_counter_only_from_matching_curve_and_entire_key() {
        let mut b = Buffer([0; 4096]);
        let key = [11; 33];
        let mut other = key;
        other[32] = 12;
        fixture(
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
        assert_eq!(inherited_counter(&b.0, 4, &identity).unwrap(), 9);
        assert_eq!(inherited_counter(&b.0, 0, &identity).unwrap(), 0);
    }

    #[test]
    fn malformed_peer_and_role_count_fail_closed() {
        let key = [11; 33];
        let kind = AuthorityType::Secp256k1;
        let identity = SecpCounter {
            authority_type: kind,
            public_key: key,
            counter: 18,
        };
        let mut b = Buffer([0; 4096]);
        fixture(&mut b, &[(kind, key, 18), (kind, key, 17)]);
        b.0[56 + 2..56 + 4].copy_from_slice(&32u16.to_le_bytes());
        assert_eq!(
            advance_counters(&mut b.0, Some(2), 0, &identity),
            Err(ProgramError::InvalidAccountData)
        );
        assert_eq!(
            inherited_counter(&b.0, 2, &identity),
            Err(ProgramError::InvalidAccountData)
        );
        let mut b = Buffer([0; 4096]);
        fixture(&mut b, &[(kind, key, 18)]);
        assert_eq!(
            advance_counters(&mut b.0[..56], Some(2), 0, &identity),
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
        assert!(
            authenticate_role(&mut b.0, Some(1), 1, &[], &[], &[], 100, false)
                .unwrap()
                .is_none()
        );
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
