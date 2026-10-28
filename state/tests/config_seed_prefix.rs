use pinocchio::program_error::ProgramError;
use swig_state::{
    reservation::DOMAIN,
    swig::{config_seeds, Swig},
    tail::{
        active_sub_account_count, config_seed_prefix, rent_claimer, SavedTail, TailKind,
        MAX_TAIL_LEN, TAIL_HEADER_LEN,
    },
    IntoBytes, SwigStateError,
};

fn entry(prefix: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; TAIL_HEADER_LEN + prefix.len()];
    config_seed_prefix::write(&mut bytes, prefix).unwrap();
    bytes
}

#[test]
fn prefix_round_trips_and_absence_preserves_legacy_default() {
    for prefix in [b"x".as_slice(), DOMAIN, &[7; 32]] {
        let bytes = entry(prefix);
        assert_eq!(bytes[0], 4); // Kind 3 is allocated to authorization locks.
        assert_eq!(config_seed_prefix::read(&bytes).unwrap(), prefix);
    }
    assert_eq!(config_seed_prefix::read(&[]).unwrap(), b"swig");
    let legacy_tail = [
        rent_claimer::entry(&[1; 32]).as_slice(),
        active_sub_account_count::entry(2).as_slice(),
    ]
    .concat();
    assert_eq!(config_seed_prefix::read(&legacy_tail).unwrap(), b"swig");
}

#[test]
fn strict_prefix_reader_rejects_malformed_and_duplicate_entries() {
    let valid = entry(DOMAIN);
    let mut invalid = vec![
        valid[..valid.len() - 1].to_vec(),
        [valid.as_slice(), valid.as_slice()].concat(),
    ];
    for len in 1..TAIL_HEADER_LEN {
        invalid.push(valid[..len].to_vec());
    }
    for offset in [1, 4, 5, 6, 7] {
        let mut bytes = valid.clone();
        bytes[offset] ^= 1;
        invalid.push(bytes);
    }
    for len in [0usize, 33] {
        let mut bytes = vec![0; TAIL_HEADER_LEN + len];
        bytes[0] = TailKind::ConfigSeedPrefix.as_u8();
        bytes[1] = config_seed_prefix::VERSION;
        bytes[2..4].copy_from_slice(&(len as u16).to_le_bytes());
        invalid.push(bytes);
    }
    for bytes in invalid {
        assert_eq!(
            config_seed_prefix::read(&bytes),
            Err(ProgramError::Custom(
                SwigStateError::InvalidSeedPrefix as u32
            ))
        );
        assert!(SavedTail::take(&bytes).is_err());
    }
    // A trailing unknown entry is still a general tail-layout error.
    assert_eq!(
        config_seed_prefix::read(&[valid.as_slice(), &[0]].concat()),
        Err(SwigStateError::InvalidRentClaimerLayout.into())
    );
}

#[test]
fn all_tail_kinds_survive_growth_and_shrink_in_any_order_at_maximum_size() {
    let entries = [
        entry(&[7; 32]),
        rent_claimer::entry(&[1; 32]).to_vec(),
        active_sub_account_count::entry(2).to_vec(),
    ];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let tail = order
            .into_iter()
            .flat_map(|i| entries[i].clone())
            .collect::<Vec<_>>();
        assert_eq!(tail.len(), MAX_TAIL_LEN);
        let saved = SavedTail::take(&tail).unwrap();
        for roles_end in [48, 1024, 64] {
            let mut account = vec![0; roles_end + tail.len()];
            saved.restore(&mut account).unwrap();
            assert_eq!(&account[roles_end..], tail);
            assert_eq!(
                config_seed_prefix::read(&account[roles_end..]).unwrap(),
                &[7; 32]
            );
        }
    }
}

#[test]
fn writer_rejects_invalid_lengths_without_changing_destination() {
    for (len, prefix) in [
        (8, vec![]),
        (41, vec![1; 33]),
        (TAIL_HEADER_LEN + DOMAIN.len() - 1, DOMAIN.to_vec()),
        (TAIL_HEADER_LEN + DOMAIN.len() + 1, DOMAIN.to_vec()),
    ] {
        let mut bytes = vec![9; len];
        assert_eq!(
            config_seed_prefix::write(&mut bytes, &prefix),
            Err(SwigStateError::InvalidSeedPrefix.into())
        );
        assert_eq!(bytes, vec![9; len]);
    }
}

#[test]
fn config_seed_loader_reads_both_namespaces_and_rejects_invalid_state() {
    let state = Swig::new([42; 32], 253, 254);
    let legacy = state.into_bytes().unwrap().to_vec();
    let reserved = [legacy.as_slice(), &entry(DOMAIN)].concat();
    for (data, prefix) in [(&legacy, b"swig".as_slice()), (&reserved, DOMAIN)] {
        let seeds = config_seeds(data).unwrap();
        assert_eq!(seeds, [prefix, &[42; 32], &[253]]);
    }
    assert!(config_seeds(&[]).is_err());
    assert!(config_seeds(&legacy[..47]).is_err());
    let mut closed = reserved.clone();
    closed[0] = 255;
    assert!(config_seeds(&closed).is_err());
    let mut corrupt = reserved;
    corrupt.pop();
    assert_eq!(
        config_seeds(&corrupt),
        Err(SwigStateError::InvalidSeedPrefix.into())
    );
}
