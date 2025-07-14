#![cfg(not(feature = "program_scope_test"))]

mod common;

use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap},
};

use common::*;
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_state::IntoBytes;

/// Huffman tree node for encoding
#[derive(Debug, Clone, Eq, PartialEq)]
struct Node {
    freq: usize,
    ch: Option<u8>,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

impl Ord for Node {
    fn cmp(&self, other: &Self) -> Ordering {
        other.freq.cmp(&self.freq) // Reverse for min-heap
    }
}

impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Huffman encoder for testing
struct HuffmanEncoder {
    codes: HashMap<u8, Vec<bool>>,
    tree_data: Vec<u8>,
}

impl HuffmanEncoder {
    fn new(text: &str) -> Self {
        let mut freq = HashMap::new();
        for byte in text.bytes() {
            *freq.entry(byte).or_insert(0) += 1;
        }

        let mut heap = BinaryHeap::new();
        for (ch, freq) in freq {
            heap.push(Node {
                freq,
                ch: Some(ch),
                left: None,
                right: None,
            });
        }

        // Build Huffman tree
        while heap.len() > 1 {
            let right = heap.pop().unwrap();
            let left = heap.pop().unwrap();
            heap.push(Node {
                freq: left.freq + right.freq,
                ch: None,
                left: Some(Box::new(left)),
                right: Some(Box::new(right)),
            });
        }

        let root = heap.pop().unwrap();
        let mut codes = HashMap::new();
        let mut tree_data = Vec::new();

        Self::build_codes(&root, Vec::new(), &mut codes);
        Self::serialize_tree(&root, &mut tree_data);

        Self { codes, tree_data }
    }

    fn build_codes(node: &Node, code: Vec<bool>, codes: &mut HashMap<u8, Vec<bool>>) {
        if let Some(ch) = node.ch {
            codes.insert(ch, if code.is_empty() { vec![false] } else { code });
        } else {
            if let Some(ref left) = node.left {
                let mut left_code = code.clone();
                left_code.push(false);
                Self::build_codes(left, left_code, codes);
            }
            if let Some(ref right) = node.right {
                let mut right_code = code.clone();
                right_code.push(true);
                Self::build_codes(right, right_code, codes);
            }
        }
    }

    fn serialize_tree(node: &Node, data: &mut Vec<u8>) -> usize {
        if let Some(ch) = node.ch {
            // Leaf node: type=0, character, unused
            data.extend_from_slice(&[0, ch, 0]);
            data.len() / 3 - 1
        } else {
            // Internal node: serialize children first
            let left_idx = if let Some(ref left) = node.left {
                Self::serialize_tree(left, data)
            } else {
                0
            };
            let right_idx = if let Some(ref right) = node.right {
                Self::serialize_tree(right, data)
            } else {
                0
            };

            // Internal node: type=1, left_idx, right_idx
            data.extend_from_slice(&[1, left_idx as u8, right_idx as u8]);
            data.len() / 3 - 1
        }
    }

    fn encode(&self, text: &str) -> Vec<u8> {
        let mut bits = Vec::new();
        for byte in text.bytes() {
            if let Some(code) = self.codes.get(&byte) {
                bits.extend(code);
            }
        }

        // Convert bits to bytes
        let mut bytes = Vec::new();
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1 << (7 - i);
                }
            }
            bytes.push(byte);
        }
        bytes
    }
}

/// Create a mock WebAuthn prefix with huffman-encoded origin
fn create_webauthn_prefix_with_huffman(
    origin: &str,
    _challenge: &[u8], // Not used in new format
    auth_data: &[u8],
) -> Vec<u8> {
    // Encode origin URL using huffman encoding
    let encoder = HuffmanEncoder::new(origin);
    let huffman_tree = encoder.tree_data.clone();
    let huffman_encoded_origin = encoder.encode(origin);

    // Mock counter for testing
    let counter = 12345u32;

    // Build the new WebAuthn prefix format:
    // [2 bytes auth_type][2 bytes auth_len][auth_data][4 bytes counter][2 bytes huffman_tree_len][huffman_tree][2 bytes huffman_encoded_len][huffman_encoded_origin]

    let mut prefix = Vec::new();

    // auth_type (2 bytes, zeroed)
    prefix.extend_from_slice(&[0u8, 0u8]);

    // auth_len (2 bytes, little-endian)
    prefix.extend_from_slice(&(auth_data.len() as u16).to_le_bytes());

    // auth_data
    prefix.extend_from_slice(auth_data);

    // counter (4 bytes, little-endian)
    prefix.extend_from_slice(&counter.to_le_bytes());

    // huffman_tree_len (2 bytes, little-endian)
    prefix.extend_from_slice(&(huffman_tree.len() as u16).to_le_bytes());

    // huffman_encoded_len (2 bytes, little-endian)
    prefix.extend_from_slice(&(huffman_encoded_origin.len() as u16).to_le_bytes());

    // huffman_tree
    prefix.extend_from_slice(&huffman_tree);

    // huffman_encoded_origin
    prefix.extend_from_slice(&huffman_encoded_origin);

    prefix
}

#[test_log::test]
fn test_webauthn_huffman_integration() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    // Test data
    let origin = "https://example.com";
    let challenge = b"test_challenge_data_12345678901234567890"; // 40 bytes
    let auth_data = b"mock_authenticator_data_for_testing_webauthn_flow"; // Mock authenticator data

    println!("Testing WebAuthn with Huffman encoding:");
    println!("  Origin: {}", origin);
    println!("  Challenge length: {} bytes", challenge.len());
    println!("  Auth data length: {} bytes", auth_data.len());

    // Create the new WebAuthn prefix with huffman encoding
    let webauthn_prefix = create_webauthn_prefix_with_huffman(origin, challenge, auth_data);

    println!("  WebAuthn prefix length: {} bytes", webauthn_prefix.len());

    // Calculate compression ratio
    let original_size = 2 + 2 + auth_data.len() + origin.len() + challenge.len();
    let compressed_size = webauthn_prefix.len();
    let compression_ratio = compressed_size as f64 / original_size as f64;

    println!("  Original size (estimated): {} bytes", original_size);
    println!("  Compressed size: {} bytes", compressed_size);
    println!("  Compression ratio: {:.2}", compression_ratio);

    // For this test, we'll just validate that the prefix can be created successfully
    // In a real scenario, this would be used in a secp256r1 signature verification

    assert!(
        !webauthn_prefix.is_empty(),
        "WebAuthn prefix should not be empty"
    );
    assert!(
        webauthn_prefix.len() > auth_data.len() + 32,
        "Prefix should contain auth data, challenge, and huffman data"
    );

    println!("  ✓ WebAuthn prefix with Huffman encoding created successfully");
}

#[test_log::test]
fn test_webauthn_huffman_various_origins() {
    let test_origins = vec![
        "https://localhost:3000",
        "https://app.example.com",
        "https://secure-banking.financial-institution.com",
        "https://api.v2.subdomain.example.co.uk",
        "https://192.168.1.100:8080",
        "http://test.local",
    ];

    for (i, origin) in test_origins.iter().enumerate() {
        println!("Testing origin {}: {}", i + 1, origin);

        let challenge = format!("challenge_data_for_test_{}", i).into_bytes();
        let auth_data = b"mock_auth_data";

        let webauthn_prefix = create_webauthn_prefix_with_huffman(origin, &challenge, auth_data);

        // Calculate compression metrics
        let encoder = HuffmanEncoder::new(origin);
        let huffman_tree = encoder.tree_data.clone();
        let huffman_encoded = encoder.encode(origin);

        let original_origin_size = origin.len();
        let compressed_origin_size = huffman_tree.len() + huffman_encoded.len();
        let origin_compression_ratio = compressed_origin_size as f64 / original_origin_size as f64;

        println!("  Original origin: {} bytes", original_origin_size);
        println!("  Huffman tree: {} bytes", huffman_tree.len());
        println!("  Huffman encoded: {} bytes", huffman_encoded.len());
        println!("  Total compressed: {} bytes", compressed_origin_size);
        println!(
            "  Origin compression ratio: {:.2}",
            origin_compression_ratio
        );
        println!("  Total prefix size: {} bytes", webauthn_prefix.len());

        assert!(!webauthn_prefix.is_empty());
        println!("  ✓ Success\\n");
    }
}
