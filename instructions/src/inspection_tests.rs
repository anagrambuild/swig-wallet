use super::*;

static KEYS: [Pubkey; 4] = [[1; 32], [2; 32], [3; 32], [4; 32]];

struct MockLookup;
struct MockAccount(&'static Pubkey);

impl<'a> AccountProxy<'a> for MockAccount {
    fn signer(&self) -> bool {
        self.0 == &KEYS[2]
    }
    fn writable(&self) -> bool {
        true
    }
    fn pubkey(&self) -> &'a Pubkey {
        self.0
    }
    fn into_account(self) -> Account<'a> {
        // This inert test-only value has raw pointers, integers, bools and
        // PhantomData; all-zero is valid. It is never passed to execute or
        // dereferenced, only carried in the original parser's output vector.
        unsafe { core::mem::zeroed() }
    }
}

#[test]
fn inspection_keeps_all_bounds_checks_and_error_order() {
    for (bytes, expected) in [
        (vec![1], InstructionError::MissingData),
        (vec![1, 4], InstructionError::MissingAccountInfo),
        (vec![1, 0, 255], InstructionError::InvalidAccountCount),
        (vec![1, 0, 3, 0, 1], InstructionError::MissingData),
        // Even an unused account index must be checked before the data header.
        (vec![1, 0, 3, 0, 1, 4], InstructionError::MissingAccountInfo),
        (vec![1, 0, 1, 1, 2, 0, 7], InstructionError::MissingData),
    ] {
        let expected = expected as u32;
        assert_eq!(
            iter(&bytes).next().unwrap().err().map(|e| e as u32),
            Some(expected)
        );
        assert_eq!(
            iter(&bytes)
                .next_inspection()
                .unwrap()
                .err()
                .map(|e| e as u32),
            Some(expected)
        );
    }
    assert!(matches!(
        InstructionIterator::new(&[], &[], &KEYS[0], &[]),
        Err(InstructionError::MissingInstructions)
    ));
}

#[test]
fn execution_keeps_wallet_signer_outer_signer_and_restricted_key_rules() {
    let bytes = [1, 0, 3, 0, 1, 2, 0, 0];
    let instruction = iter(&bytes).next().unwrap().ok().unwrap();
    assert_eq!(instruction.cpi_accounts.len(), 3);
    assert!(instruction.uses_swig_signer);
    assert_eq!(
        instruction
            .accounts
            .iter()
            .map(|a| a.is_signer)
            .collect::<Vec<_>>(),
        [true, false, true]
    );
    assert!(instruction.accounts.iter().all(|a| a.is_writable));

    let restricted = [&KEYS[0], &KEYS[2]];
    let mut iterator = iter(&bytes);
    iterator.restricted_keys = &restricted;
    let instruction = iterator.next().unwrap().ok().unwrap();
    assert!(!instruction.uses_swig_signer);
    assert!(instruction.accounts.iter().all(|a| !a.is_signer));
}

impl<'a> AccountLookup<'a, MockAccount> for MockLookup {
    fn get_account(&self, index: usize) -> Result<MockAccount, InstructionError> {
        KEYS.get(index)
            .map(MockAccount)
            .ok_or(InstructionError::MissingAccountInfo)
    }
    fn size(&self) -> usize {
        KEYS.len()
    }
}

fn iter(data: &[u8]) -> InstructionIterator<'_, MockLookup, &[&Pubkey], MockAccount> {
    InstructionIterator {
        accounts: MockLookup,
        data,
        cursor: 1,
        remaining: data[0] as usize,
        restricted_keys: &[],
        signer: &KEYS[0],
        _phantom: PhantomData,
    }
}

fn compare(data: &[u8]) {
    // Both public entry points use the same existing constructor, which
    // rejects empty input before selecting the parsing mode.
    if data.is_empty() {
        return;
    }
    let mut full = iter(data);
    let mut inspection = iter(data);
    loop {
        let left = full.next().map(|r| {
            r.map(|i| (*i.program_id, i.indexes.to_vec(), i.data.to_vec()))
                .map_err(|e| e as u32)
        });
        let right = inspection.next_inspection().map(|r| {
            r.map(|i| (*i.program_id, i.indexes.to_vec(), i.data.to_vec()))
                .map_err(|e| e as u32)
        });
        assert_eq!(left, right, "payload {data:?}");
        assert_eq!(full.cursor, inspection.cursor);
        assert_eq!(full.remaining, inspection.remaining);
        if left.is_none() {
            break;
        }
    }
}

#[test]
fn inspection_matches_full_parser_for_valid_and_malformed_payloads() {
    let mut payload = vec![3];
    for (program, indexes, bytes) in [
        (0, vec![1, 2], vec![2, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0]),
        (1, vec![0, 1, 3], vec![12, 10, 0, 0, 0, 0, 0, 0, 0, 9]),
        (2, vec![], vec![]),
    ] {
        payload.extend_from_slice(&[program, indexes.len() as u8]);
        payload.extend(indexes);
        payload.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        payload.extend(bytes);
    }
    for end in 1..=payload.len() {
        compare(&payload[..end]);
    }
    for offset in 0..payload.len() {
        for byte in 0..=255u8 {
            let mut changed = payload.clone();
            changed[offset] = byte;
            compare(&changed);
        }
    }
    for count in [0, 1, 253, 254, 255] {
        let mut bytes = vec![1, 0, count];
        bytes.extend(std::iter::repeat_n(1, count as usize));
        bytes.extend_from_slice(&[0, 0]);
        compare(&bytes);
    }
    let mut seed = 0x5678_4321_9234_1234u64;
    for n in 1..=10_000usize {
        let mut bytes = vec![0; n % 128 + 1];
        for byte in &mut bytes {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *byte = seed as u8;
        }
        bytes[0] %= 5;
        compare(&bytes);
    }
}
