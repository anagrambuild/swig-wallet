#![allow(dead_code)]
//! Reusable harness for asserting swig-account stability across the
//! *size-modifying* instructions — add/remove/update authority, V2 sub-account
//! create, and set-rent-claimer — each of which reallocs the swig account.
//!
//! The pattern is always the same: snapshot the account, run an op that grows
//! or shrinks it, then assert that every *unrelated* role and the rent-claimer
//! tail survived byte-for-byte. Roles are matched by authority identity (not by
//! role id), so the assertions are robust to roles being added or removed.
//!
//! ```ignore
//! let before = SwigSnapshot::capture(&context, &swig);
//! // ... an op that reallocs the account (e.g. creator makes a sub-account) ...
//! let after = SwigSnapshot::capture(&context, &swig);
//! before.assert_others_stable(&after, &[creator.pubkey().to_bytes()]); // only creator changed
//! ```

use solana_sdk::pubkey::Pubkey;
use swig_state::{
    action::{Action, Permission},
    swig::{Swig, SwigWithRoles},
    tail::rent_claimer,
    Transmutable,
};

use super::SwigTestContext;

/// A role's permissions as `(permission, body-bytes)` pairs, in on-chain order.
pub type ActionList = Vec<(Permission, Vec<u8>)>;

/// One role's on-chain identity and permission list.
#[derive(Clone, Debug, PartialEq)]
pub struct RoleSnapshot {
    pub id: u32,
    pub identity: Vec<u8>,
    pub actions: ActionList,
}

/// A comparable snapshot of a swig account's mutable regions: the roles (each
/// with its authority + actions), the rent-claimer tail, the sub-account
/// counter, and the total account length.
#[derive(Clone, Debug)]
pub struct SwigSnapshot {
    pub account_len: usize,
    pub counter: u32,
    pub rent_claimer: Option<[u8; 32]>,
    pub roles: Vec<RoleSnapshot>,
}

impl SwigSnapshot {
    /// Capture the current state of `swig_key`.
    pub fn capture(context: &SwigTestContext, swig_key: &Pubkey) -> Self {
        let data = context.svm.get_account(swig_key).unwrap().data;
        let tail = Swig::split_parts(&data).unwrap().tail.to_vec();
        let with_roles = SwigWithRoles::from_bytes(&data).unwrap();
        let counter = with_roles.state.sub_account_counter;

        let mut roles = Vec::new();
        for id in 0..with_roles.state.roles as u32 {
            let role = with_roles.get_role(id).unwrap().unwrap();
            roles.push(RoleSnapshot {
                id,
                identity: role.authority.identity().unwrap().to_vec(),
                actions: decode_actions(role.actions, role.position.num_actions()),
            });
        }

        let rent_claimer = rent_claimer::read_strict(&tail).unwrap().copied();
        Self {
            account_len: data.len(),
            counter,
            rent_claimer,
            roles,
        }
    }

    /// Look up a role by its authority identity (its pubkey, for Ed25519).
    pub fn role_by_identity(&self, identity: &[u8]) -> Option<&RoleSnapshot> {
        self.roles.iter().find(|r| r.identity == identity)
    }

    /// The action list for the given authority, or panics if it is absent.
    pub fn actions_of(&self, identity: &[u8]) -> &ActionList {
        &self
            .role_by_identity(identity)
            .unwrap_or_else(|| panic!("no role for the given authority"))
            .actions
    }

    /// Assert the rent-claimer tail is byte-identical between `self` and `after`.
    pub fn assert_claimer_unchanged(&self, after: &SwigSnapshot) {
        assert_eq!(
            self.rent_claimer, after.rent_claimer,
            "rent claimer changed across the op"
        );
    }

    /// Assert that every role present in `self` whose identity is NOT listed in
    /// `changed` still exists in `after` with byte-identical authority and
    /// actions, and that the rent claimer is unchanged.
    ///
    /// Pass the identities you *expect* the op to touch (the added/removed/
    /// updated authorities) in `changed`; everything else must be untouched.
    pub fn assert_others_stable(&self, after: &SwigSnapshot, changed: &[[u8; 32]]) {
        self.assert_claimer_unchanged(after);
        for before in &self.roles {
            if changed
                .iter()
                .any(|c| c.as_slice() == before.identity.as_slice())
            {
                continue;
            }
            let now = after.role_by_identity(&before.identity).unwrap_or_else(|| {
                panic!(
                    "an unrelated role (was id {}) disappeared after the op",
                    before.id
                )
            });
            assert_eq!(
                now.actions, before.actions,
                "an unrelated role (was id {}) had its permissions corrupted by the realloc",
                before.id
            );
        }
    }
}

fn decode_actions(actions: &[u8], num_actions: u16) -> ActionList {
    let mut out = Vec::new();
    let mut cursor = 0;
    for _ in 0..num_actions {
        let header =
            unsafe { Action::load_unchecked(&actions[cursor..cursor + Action::LEN]).unwrap() };
        cursor += Action::LEN;
        let len = header.length() as usize;
        out.push((
            header.permission().unwrap(),
            actions[cursor..cursor + len].to_vec(),
        ));
        cursor += len;
    }
    out
}

/// The 8-byte body of a scoped V2 action: `subacc_id` little-endian + 4 zero
/// padding bytes. Matches both the auto-granted `SubAccountV2All` and any
/// manually-added scoped V2 permission.
pub fn scoped_v2_body(subacc_id: u32) -> Vec<u8> {
    let mut b = subacc_id.to_le_bytes().to_vec();
    b.extend_from_slice(&[0u8; 4]);
    b
}
