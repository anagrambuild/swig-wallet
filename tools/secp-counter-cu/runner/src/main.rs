use litesvm::LiteSVM;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
    pkey::Private,
};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};

struct Harness {
    svm: LiteSVM,
    payer: Keypair,
    program: Pubkey,
    state: Pubkey,
    k1: libsecp256k1::SecretKey,
    r1: EcKey<Private>,
}
impl Harness {
    fn key(&self, kind: u16) -> [u8; 33] {
        if kind == 1 {
            let mut k = [0; 33];
            k[..32].copy_from_slice(self.payer.pubkey().as_ref());
            k
        } else if kind <= 4 {
            libsecp256k1::PublicKey::from_secret_key(&self.k1).serialize_compressed()
        } else {
            self.r1
                .public_key()
                .to_bytes(
                    self.r1.group(),
                    PointConversionForm::COMPRESSED,
                    &mut BigNumContext::new().unwrap(),
                )
                .unwrap()
                .try_into()
                .unwrap()
        }
    }
    fn fixture(
        &self,
        kind: u16,
        n: usize,
        duplicate: Option<usize>,
        session_peer: bool,
    ) -> (Vec<u8>, Vec<usize>) {
        let mut b = vec![0; 48];
        b[0] = 1;
        b[34..36].copy_from_slice(&(n as u16).to_le_bytes());
        b[36..40].copy_from_slice(&(n as u32).to_le_bytes());
        let key = self.key(kind);
        let mut offsets = Vec::new();
        for i in 0..n {
            let k = if session_peer && duplicate == Some(i) {
                kind + 1
            } else {
                kind
            };
            let len = if k == 1 {
                32
            } else if k == 4 || k == 6 {
                88
            } else {
                40
            };
            let at = b.len();
            let end = at + 16 + len + 8;
            b.resize(end, 0);
            offsets.push(at);
            b[at..at + 2].copy_from_slice(&k.to_le_bytes());
            b[at + 2..at + 4].copy_from_slice(&(len as u16).to_le_bytes());
            b[at + 4..at + 6].copy_from_slice(&1u16.to_le_bytes());
            b[end - 8..end - 6].copy_from_slice(&7u16.to_le_bytes());
            b[end - 4..end].copy_from_slice(&8u32.to_le_bytes());
            b[at + 8..at + 12].copy_from_slice(&(i as u32).to_le_bytes());
            b[at + 12..at + 16].copy_from_slice(&((end - 48) as u32).to_le_bytes());
            let mut candidate = key;
            if i != 0 && duplicate != Some(i) {
                if kind == 1 {
                    candidate[1..9].copy_from_slice(&(i as u64).to_le_bytes());
                } else if kind <= 4 {
                    let mut scalar = [0; 32];
                    scalar[24..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
                    candidate = libsecp256k1::PublicKey::from_secret_key(
                        &libsecp256k1::SecretKey::parse(&scalar).unwrap(),
                    )
                    .serialize_compressed();
                } else {
                    let mut ctx = BigNumContext::new().unwrap();
                    let mut point = EcPoint::new(self.r1.group()).unwrap();
                    point
                        .mul_generator2(
                            self.r1.group(),
                            &BigNum::from_u32(i as u32 + 1).unwrap(),
                            &mut ctx,
                        )
                        .unwrap();
                    candidate = point
                        .to_bytes(self.r1.group(), PointConversionForm::COMPRESSED, &mut ctx)
                        .unwrap()
                        .try_into()
                        .unwrap();
                }
            }
            let kl = if k == 1 { 32 } else { 33 };
            b[at + 16..at + 16 + kl].copy_from_slice(&candidate[..kl]);
            if k != 1 {
                b[at + 52..at + 56].copy_from_slice(&17u32.to_le_bytes());
            }
            if k == 4 || k == 6 {
                b[at + 56..at + 88].copy_from_slice(self.payer.pubkey().as_ref());
                b[at + 96..at + 104].copy_from_slice(&200u64.to_le_bytes());
            }
        }
        (b, offsets)
    }
    fn transaction(
        &self,
        kind: u16,
        mode: u8,
        selected: u32,
        counter: u32,
        session: bool,
    ) -> VersionedTransaction {
        let sysvar = solana_sdk::sysvar::instructions::id();
        let metas = vec![
            AccountMeta::new(self.state, false),
            AccountMeta::new(self.payer.pubkey(), true),
            AccountMeta::new_readonly(sysvar, false),
        ];
        let mut instructions = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
        let payload = if kind == 1 || session {
            vec![1]
        } else {
            let mut signed = b"counter-cu".to_vec();
            for m in &metas {
                signed.extend_from_slice(m.pubkey.as_ref());
                signed.push(m.is_writable as u8);
                signed.push(m.is_signer as u8);
                signed.extend_from_slice(&[0; 6]);
            }
            signed.extend_from_slice(&100u64.to_le_bytes());
            signed.extend_from_slice(&counter.to_le_bytes());
            let mut p = 100u64.to_le_bytes().to_vec();
            p.extend_from_slice(&counter.to_le_bytes());
            if kind <= 4 {
                let digest = solana_sdk::hash::hash(&signed);
                let message = hex::encode(digest.to_bytes());
                let hash = solana_keccak_hasher::hash(message.as_bytes());
                let (sig, recovery) =
                    libsecp256k1::sign(&libsecp256k1::Message::parse(&hash.to_bytes()), &self.k1);
                p.extend_from_slice(&sig.serialize());
                p.push(recovery.serialize() + 27);
            } else {
                let message = solana_keccak_hasher::hash(&signed).to_bytes();
                let sig = solana_secp256r1_program::sign_message(
                    &message,
                    &self.r1.private_key_to_der().unwrap(),
                )
                .unwrap();
                instructions.push(
                    solana_secp256r1_program::new_secp256r1_instruction_with_signature(
                        &message,
                        &sig,
                        &self.key(kind),
                    ),
                );
                p.push(2);
                p.extend_from_slice(&[0; 4]);
            }
            p
        };
        let mut data = vec![mode];
        data.extend_from_slice(&selected.to_le_bytes());
        data.push(0);
        // create_session selects root authentication for a session authority.
        data[5] = u8::from((kind == 4 || kind == 6) && !session);
        data.extend_from_slice(&payload);
        instructions.push(Instruction {
            program_id: self.program,
            accounts: metas,
            data,
        });
        let msg = v0::Message::try_compile(
            &self.payer.pubkey(),
            &instructions,
            &[],
            self.svm.latest_blockhash(),
        )
        .unwrap();
        VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&self.payer]).unwrap()
    }
    fn set(&mut self, data: Vec<u8>) {
        self.svm
            .set_account(
                self.state,
                Account {
                    lamports: 10_000_000_000,
                    data,
                    owner: self.program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    }
}
fn index_comparison(h: &mut Harness) {
    println!("kind,roles,selected,scenario,mode,cu,heap_bytes,status");
    for kind in [1u16, 3, 5] {
        for n in [9usize, 10, 100, 512, 1000] {
            for selected in [0, n / 2, n - 1] {
                for scenario in ["none", "pair", "last_pair", "legacy", "all"] {
                    if kind == 1 && scenario != "none" {
                        continue;
                    }
                    let (mut data, offsets) = h.fixture(kind, n, None, false);
                    let key_len = if kind == 1 { 32 } else { 33 };
                    let previous_key =
                        data[offsets[selected] + 16..offsets[selected] + 16 + key_len].to_vec();
                    data[offsets[0] + 16..offsets[0] + 16 + key_len].copy_from_slice(&previous_key);
                    data[offsets[selected] + 16..offsets[selected] + 16 + key_len]
                        .copy_from_slice(&h.key(kind)[..key_len]);
                    let peer = if scenario == "last_pair" && selected != n - 1 {
                        n - 1
                    } else if selected == 0 {
                        1
                    } else {
                        0
                    };
                    if matches!(scenario, "pair" | "last_pair" | "legacy") {
                        data[offsets[peer] + 16..offsets[peer] + 49].copy_from_slice(&h.key(kind));
                    } else if scenario == "all" {
                        for at in &offsets {
                            data[at + 16..at + 49].copy_from_slice(&h.key(kind));
                        }
                    }
                    let counter = if scenario == "legacy" {
                        data[offsets[selected] + 52..offsets[selected] + 56]
                            .copy_from_slice(&27u32.to_le_bytes());
                        data[offsets[peer] + 52..offsets[peer] + 56]
                            .copy_from_slice(&100u32.to_le_bytes());
                        28
                    } else {
                        18
                    };
                    for mode in [0u8, 1, 5, 7] {
                        h.set(data.clone());
                        let result = h.svm.send_transaction(h.transaction(
                            kind,
                            mode,
                            selected as u32,
                            counter,
                            false,
                        ));
                        match result {
                            Ok(result) => {
                                let mut expected = data.clone();
                                if kind != 1 {
                                    for (i, at) in offsets.iter().enumerate() {
                                        if i == selected
                                            || (mode != 0
                                                && (scenario == "all"
                                                    || (scenario != "none" && i == peer)))
                                        {
                                            let next: u32 = if mode != 0 && scenario == "legacy" {
                                                101
                                            } else {
                                                counter
                                            };
                                            expected[at + 52..at + 56]
                                                .copy_from_slice(&next.to_le_bytes());
                                        }
                                    }
                                }
                                assert_eq!(h.svm.get_account(&h.state).unwrap().data, expected, "kind={kind} n={n} selected={selected} scenario={scenario} mode={mode}");
                                let heap =
                                    u64::from_le_bytes(result.return_data.data.try_into().unwrap());
                                println!(
                                    "{kind},{n},{selected},{scenario},{mode},{},{heap},ok",
                                    result.compute_units_consumed
                                );
                            },
                            Err(error) => {
                                let out_of_memory = error
                                    .meta
                                    .logs
                                    .iter()
                                    .any(|line| line.contains("memory allocation failed"));
                                assert!(
                                    mode == 5 && out_of_memory,
                                    "unexpected mode={mode} kind={kind} n={n}: {error:?}"
                                );
                                assert_eq!(h.svm.get_account(&h.state).unwrap().data, data);
                                println!(
                                    "{kind},{n},{selected},{scenario},{mode},{},,out_of_memory",
                                    error.meta.compute_units_consumed
                                );
                            },
                        }
                        h.svm.expire_blockhash();
                    }
                }
            }
        }
    }
}

fn index_edge_cases(h: &mut Harness, mode: u8) {
    for kind in [3u16, 5] {
        // Duplicates before and after the selected role, plus lookalike nonmatches.
        for selected in [0usize, 2, 5] {
            for maximum in [100u32, u32::MAX] {
                let (mut data, offsets) = h.fixture(kind, 6, None, false);
                for i in [0, 2, 5] {
                    data[offsets[i] + 16..offsets[i] + 49].copy_from_slice(&h.key(kind));
                    data[offsets[i] + 52..offsets[i] + 56].copy_from_slice(&27u32.to_le_bytes());
                }
                data[offsets[2] + 52..offsets[2] + 56].copy_from_slice(&maximum.to_le_bytes());
                // Same curve and eight-byte prefix, different full key.
                data[offsets[1] + 16..offsets[1] + 49].copy_from_slice(&h.key(kind));
                data[offsets[1] + 48] ^= 1;
                // Same full bytes, different curve.
                data[offsets[3]..offsets[3] + 2]
                    .copy_from_slice(&(if kind == 3 { 5u16 } else { 3u16 }).to_le_bytes());
                data[offsets[3] + 16..offsets[3] + 49].copy_from_slice(&h.key(kind));
                // Same x coordinate, opposite compressed point prefix.
                data[offsets[4] + 16..offsets[4] + 49].copy_from_slice(&h.key(kind));
                data[offsets[4] + 16] ^= 1;
                let own = if selected == 2 { maximum } else { 27 };
                h.set(data.clone());
                h.svm
                    .send_transaction(h.transaction(
                        kind,
                        mode,
                        selected as u32,
                        own.wrapping_add(1),
                        false,
                    ))
                    .unwrap();
                let mut expected = data;
                for i in [0, 2, 5] {
                    expected[offsets[i] + 52..offsets[i] + 56]
                        .copy_from_slice(&maximum.wrapping_add(1).to_le_bytes());
                }
                assert_eq!(h.svm.get_account(&h.state).unwrap().data, expected);
                h.svm.expire_blockhash();
            }
        }
        // A role-shaped tail is neither considered a peer nor selectable by ID.
        let (mut data, offsets) = h.fixture(kind, 3, Some(1), false);
        data[34..36].copy_from_slice(&2u16.to_le_bytes());
        data[offsets[2] + 16..offsets[2] + 49].copy_from_slice(&h.key(kind));
        data[offsets[2] + 52..offsets[2] + 56].copy_from_slice(&1000u32.to_le_bytes());
        h.set(data.clone());
        h.svm
            .send_transaction(h.transaction(kind, mode, 0, 18, false))
            .unwrap();
        let mut expected = data;
        for at in &offsets[..2] {
            expected[at + 52..at + 56].copy_from_slice(&18u32.to_le_bytes());
        }
        assert_eq!(h.svm.get_account(&h.state).unwrap().data, expected);
        h.svm.expire_blockhash();
        let err = h
            .svm
            .send_transaction(h.transaction(kind, mode, 2, 1001, false))
            .unwrap_err();
        assert!(matches!(
            err.err,
            TransactionError::InstructionError(_, InstructionError::InvalidAccountData)
        ));
        assert_eq!(h.svm.get_account(&h.state).unwrap().data, expected);
        h.svm.expire_blockhash();
    }
}

fn main() {
    let so = std::env::args().nth(1).expect("SBF artifact path");
    let auth_mode: u8 = std::env::args()
        .nth(2)
        .map(|s| s.parse().unwrap())
        .unwrap_or(1);
    assert!([1, 5, 7].contains(&auth_mode));
    let r1_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let r1_private = BigNum::from_slice(&[7; 32]).unwrap();
    let mut r1_public = EcPoint::new(&r1_group).unwrap();
    r1_public
        .mul_generator2(&r1_group, &r1_private, &mut BigNumContext::new().unwrap())
        .unwrap();
    let mut h = Harness {
        svm: LiteSVM::new(),
        payer: Keypair::new(),
        program: Pubkey::new_unique(),
        state: Pubkey::new_unique(),
        k1: libsecp256k1::SecretKey::parse(&[7; 32]).unwrap(),
        r1: EcKey::from_private_components(&r1_group, &r1_private, &r1_public).unwrap(),
    };
    h.svm.add_program_from_file(h.program, so).unwrap();
    h.svm.warp_to_slot(100);
    h.svm.airdrop(&h.payer.pubkey(), 10_000_000_000).unwrap();
    index_edge_cases(&mut h, auth_mode);
    if std::env::args().nth(3).as_deref() == Some("--index") {
        index_comparison(&mut h);
    } else {
        println!("kind,roles,duplicate_index,mode,cu");
        for kind in [1u16, 3, 5] {
            for n in [9usize, 10] {
                for duplicate in [None, Some(1), Some(n - 1)] {
                    if kind == 1 && duplicate.is_some() {
                        continue;
                    }
                    for mode in [0u8, auth_mode, 3] {
                        let (data, offsets) = h.fixture(kind, n, duplicate, false);
                        h.set(data.clone());
                        let tx = h.transaction(kind, mode, 0, 18, false);
                        let result = h.svm.send_transaction(tx).unwrap();
                        let mut expected = data;
                        if kind != 1 && mode != 3 {
                            for (i, at) in offsets.iter().enumerate() {
                                if i == 0 || (mode > 0 && duplicate == Some(i)) {
                                    expected[at + 52..at + 56]
                                        .copy_from_slice(&18u32.to_le_bytes());
                                }
                            }
                        }
                        assert_eq!(h.svm.get_account(&h.state).unwrap().data, expected);
                        println!(
                            "{kind},{n},{},{mode},{}",
                            duplicate.map_or(-1, |n| n as i32),
                            result.compute_units_consumed
                        );
                        h.svm.expire_blockhash();
                    }
                }
            }
        }
    }
    // Replay a valid detached signature with only the unsigned role ID changed.
    for kind in [3u16, 5] {
        let (data, offsets) = h.fixture(kind, 2, Some(1), false);
        h.set(data.clone());
        let tx = h.transaction(kind, auth_mode, 0, 18, false);
        let original_message = tx.message.clone();
        h.svm.send_transaction(tx).unwrap();
        h.svm.expire_blockhash();
        let before = h.svm.get_account(&h.state).unwrap().data;
        let mut replay_message = original_message;
        if let VersionedMessage::V0(ref mut message) = replay_message {
            message.recent_blockhash = h.svm.latest_blockhash();
            message.instructions.last_mut().unwrap().data[1..5]
                .copy_from_slice(&1u32.to_le_bytes());
        }
        let replay = VersionedTransaction::try_new(replay_message, &[&h.payer]).unwrap();
        let err = h.svm.send_transaction(replay).unwrap_err();
        let expected = if kind == 3 { 3017 } else { 3019 };
        assert!(
            matches!(
                &err.err,
                TransactionError::InstructionError(_, InstructionError::Custom(code)) if *code == expected
            ),
            "{:?}",
            err.err
        );
        assert_eq!(h.svm.get_account(&h.state).unwrap().data, before);
        h.svm.expire_blockhash();
        // A fresh signature through the peer succeeds.
        let tx = h.transaction(kind, auth_mode, 1, 19, false);
        h.svm.send_transaction(tx).unwrap();
        h.svm.expire_blockhash();
        // A genuine signature consumed under the old single-role behavior can execute
        // once through a lagging role during the accepted automatic migration.
        h.set(data.clone());
        let tx = h.transaction(kind, 0, 1, 18, false);
        let mut legacy_message = tx.message.clone();
        h.svm.send_transaction(tx).unwrap();
        h.svm.expire_blockhash();
        if let VersionedMessage::V0(ref mut message) = legacy_message {
            message.recent_blockhash = h.svm.latest_blockhash();
            message.instructions.last_mut().unwrap().data[0] = auth_mode;
            message.instructions.last_mut().unwrap().data[1..5]
                .copy_from_slice(&0u32.to_le_bytes());
        }
        let replay = VersionedTransaction::try_new(legacy_message, &[&h.payer]).unwrap();
        h.svm.send_transaction(replay).unwrap();
        h.svm.expire_blockhash();
        for at in &offsets {
            assert_eq!(
                &h.svm.get_account(&h.state).unwrap().data[at + 52..at + 56],
                &19u32.to_le_bytes()
            );
        }
        for selected in [0, 1] {
            let before = h.svm.get_account(&h.state).unwrap().data;
            let err = h
                .svm
                .send_transaction(h.transaction(kind, auth_mode, selected, 18, false))
                .unwrap_err();
            assert!(
                matches!(&err.err,
                    TransactionError::InstructionError(_, InstructionError::Custom(code)) if *code == expected
                ),
                "{:?}",
                err.err
            );
            assert_eq!(h.svm.get_account(&h.state).unwrap().data, before);
            h.svm.expire_blockhash();
        }
        // A much larger legacy gap also aligns after either role authenticates.
        for selected in [0, 1] {
            let mut unequal = data.clone();
            unequal[offsets[0] + 52..offsets[0] + 56].copy_from_slice(&27u32.to_le_bytes());
            unequal[offsets[1] + 52..offsets[1] + 56].copy_from_slice(&100u32.to_le_bytes());
            h.set(unequal);
            let counter = if selected == 0 { 28 } else { 101 };
            h.svm
                .send_transaction(h.transaction(kind, auth_mode, selected, counter, false))
                .unwrap();
            h.svm.expire_blockhash();
            for at in &offsets {
                assert_eq!(
                    &h.svm.get_account(&h.state).unwrap().data[at + 52..at + 56],
                    &101u32.to_le_bytes()
                );
            }
            // Normal operation resumes at maximum + 2, without an extra skipped counter.
            h.svm
                .send_transaction(h.transaction(kind, auth_mode, 1 - selected, 102, false))
                .unwrap();
            h.svm.expire_blockhash();
            for at in &offsets {
                assert_eq!(
                    &h.svm.get_account(&h.state).unwrap().data[at + 52..at + 56],
                    &102u32.to_le_bytes()
                );
            }
        }
        // A downstream error rolls back authentication and every peer counter write.
        let mut unequal = data.clone();
        unequal[offsets[1] + 52..offsets[1] + 56].copy_from_slice(&100u32.to_le_bytes());
        h.set(unequal.clone());
        let err = h
            .svm
            .send_transaction(h.transaction(
                kind,
                if auth_mode == 1 { 4 } else { auth_mode + 1 },
                0,
                18,
                false,
            ))
            .unwrap_err();
        assert!(
            matches!(
                &err.err,
                TransactionError::InstructionError(_, InstructionError::Custom(9999))
            ),
            "{:?}",
            err.err
        );
        assert_eq!(h.svm.get_account(&h.state).unwrap().data, unequal);
        h.svm.expire_blockhash();
        // A bad signature never triggers synchronization, even with a valid counter.
        let mut bad = h.transaction(kind, auth_mode, 0, 18, false).message;
        if let VersionedMessage::V0(ref mut message) = bad {
            let index = if kind == 3 {
                message.instructions.len() - 1
            } else {
                1
            };
            let start = if kind == 3 {
                6 + 12
            } else {
                u16::from_le_bytes(message.instructions[index].data[2..4].try_into().unwrap())
                    as usize
            };
            message.instructions[index].data[start..start + 64].fill(0);
        }
        let bad = VersionedTransaction::try_new(bad, &[&h.payer]).unwrap();
        let bad_error = h.svm.send_transaction(bad).unwrap_err();
        let invalid_signature = if kind == 3 { 3015 } else { 2 };
        assert!(
            matches!(&bad_error.err,
                TransactionError::InstructionError(1, InstructionError::Custom(code)) if *code == invalid_signature
            ),
            "{:?}",
            bad_error.err
        );
        assert_eq!(h.svm.get_account(&h.state).unwrap().data, unequal);
        h.svm.expire_blockhash();
        // A malformed later peer must also roll back writes to earlier valid peers.
        for malformed in [1, 2] {
            let (mut malformed_data, positions) = h.fixture(kind, 3, Some(1), false);
            malformed_data[positions[2] + 16..positions[2] + 49].copy_from_slice(&h.key(kind));
            malformed_data[positions[malformed] + 2..positions[malformed] + 4]
                .copy_from_slice(&32u16.to_le_bytes());
            h.set(malformed_data.clone());
            let err = h
                .svm
                .send_transaction(h.transaction(kind, auth_mode, 0, 18, false))
                .unwrap_err();
            assert!(
                matches!(
                    &err.err,
                    TransactionError::InstructionError(_, InstructionError::InvalidAccountData)
                ),
                "{:?}",
                err.err
            );
            assert_eq!(h.svm.get_account(&h.state).unwrap().data, malformed_data);
            h.svm.expire_blockhash();
        }
        // Ordinary and session-root authorities share counters; session-key signing does not.
        let (data, offsets) = h.fixture(kind, 2, Some(1), true);
        h.set(data);
        let tx = h.transaction(kind, auth_mode, 0, 18, false);
        h.svm.send_transaction(tx).unwrap();
        h.svm.expire_blockhash();
        let before = h.svm.get_account(&h.state).unwrap().data;
        let tx = h.transaction(kind + 1, auth_mode, 1, 0, true);
        h.svm.send_transaction(tx).unwrap();
        h.svm.expire_blockhash();
        assert_eq!(h.svm.get_account(&h.state).unwrap().data, before);
        let tx = h.transaction(kind + 1, auth_mode, 1, 19, false);
        h.svm.send_transaction(tx).unwrap();
        h.svm.expire_blockhash();
        for at in &offsets {
            assert_eq!(
                &h.svm.get_account(&h.state).unwrap().data[at + 52..at + 56],
                &19u32.to_le_bytes()
            );
        }
        // Authentication reads Clock internally and keeps the existing age boundary.
        for slot in [99, 2100, 2101] {
            let (data, positions) = h.fixture(kind, 2, Some(1), false);
            h.set(data.clone());
            h.svm.warp_to_slot(slot);
            let result = h
                .svm
                .send_transaction(h.transaction(kind, auth_mode, 0, 18, false));
            if slot == 2100 {
                result.unwrap();
                let mut expected = data;
                for at in positions {
                    expected[at + 52..at + 56].copy_from_slice(&18u32.to_le_bytes());
                }
                assert_eq!(h.svm.get_account(&h.state).unwrap().data, expected);
            } else {
                let err = result.unwrap_err();
                let age_error = if kind == 3 { 3015 } else { 3016 };
                assert!(
                    matches!(
                        err.err,
                        TransactionError::InstructionError(_, InstructionError::Custom(code)) if code == age_error
                    ),
                    "{:?}",
                    err.err
                );
                assert_eq!(h.svm.get_account(&h.state).unwrap().data, data);
            }
            h.svm.expire_blockhash();
        }
        h.svm.warp_to_slot(100);
    }
    eprintln!("All CU fixtures and real k1/r1 replay, rollback, legacy alignment, and session assertions passed.");
}
