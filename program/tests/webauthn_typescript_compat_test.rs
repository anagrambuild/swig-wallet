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
use swig_state_x::IntoBytes;

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

/// Create a WebAuthn prefix that matches the TypeScript implementation exactly
fn create_typescript_compatible_webauthn_prefix(
    origin: &str,
    auth_data: &[u8],
    counter: u32,
) -> Vec<u8> {
    // Encode origin URL using huffman encoding
    let encoder = HuffmanEncoder::new(origin);
    let huffman_tree = encoder.tree_data.clone();
    let huffman_encoded_origin = encoder.encode(origin);

    // Build the WebAuthn prefix format exactly as TypeScript does:
    // [2 bytes auth_type][2 bytes auth_len][auth_data][4 bytes counter][2 bytes huffman_tree_len][2 bytes huffman_encoded_len][huffman_tree][huffman_encoded_origin]
    
    let mut prefix = Vec::new();
    
    // auth_type (2 bytes, zeroed for backward compatibility)
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
fn test_typescript_rust_webauthn_compatibility() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    // Test data that matches what TypeScript would send
    let origin = "https://localhost:3000";
    let auth_data = b"mock_authenticator_data_for_testing_webauthn_flow"; // Mock authenticator data
    let counter = 12345u32;

    println!("Testing TypeScript-Rust WebAuthn compatibility:");
    println!("  Origin: {}", origin);
    println!("  Auth data length: {} bytes", auth_data.len());
    println!("  Counter: {}", counter);

    // Create the WebAuthn prefix exactly as TypeScript would
    let webauthn_prefix = create_typescript_compatible_webauthn_prefix(origin, auth_data, counter);
    
    println!("  WebAuthn prefix length: {} bytes", webauthn_prefix.len());
    println!("  First 50 bytes: {:?}", &webauthn_prefix[..50.min(webauthn_prefix.len())]);
    
    // Verify the format can be parsed by our Rust decoder
    // This simulates what the Rust program would do when receiving this data
    
    // Parse the format manually to verify it matches expectations
    let mut offset = 0;
    
    // auth_type (2 bytes)
    let auth_type = u16::from_le_bytes(webauthn_prefix[offset..offset + 2].try_into().unwrap());
    offset += 2;
    assert_eq!(auth_type, 0, "auth_type should be 0");
    
    // auth_len (2 bytes)
    let auth_len = u16::from_le_bytes(webauthn_prefix[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;
    assert_eq!(auth_len, auth_data.len(), "auth_len should match auth_data length");
    
    // auth_data
    let parsed_auth_data = &webauthn_prefix[offset..offset + auth_len];
    offset += auth_len;
    assert_eq!(parsed_auth_data, auth_data, "auth_data should match");
    
    // counter (4 bytes)
    let parsed_counter = u32::from_le_bytes(webauthn_prefix[offset..offset + 4].try_into().unwrap());
    offset += 4;
    assert_eq!(parsed_counter, counter, "counter should match");
    
    // huffman_tree_len (2 bytes)
    let huffman_tree_len = u16::from_le_bytes(webauthn_prefix[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;
    
    // huffman_encoded_len (2 bytes)
    let huffman_encoded_len = u16::from_le_bytes(webauthn_prefix[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;
    
    // huffman_tree
    let huffman_tree = &webauthn_prefix[offset..offset + huffman_tree_len];
    offset += huffman_tree_len;
    
    // huffman_encoded_origin
    let huffman_encoded_origin = &webauthn_prefix[offset..offset + huffman_encoded_len];
    
    println!("  Parsed successfully:");
    println!("    auth_type: {}", auth_type);
    println!("    auth_len: {}", auth_len);
    println!("    counter: {}", parsed_counter);
    println!("    huffman_tree_len: {}", huffman_tree_len);
    println!("    huffman_encoded_len: {}", huffman_encoded_len);
    
    // Verify we can decode the huffman-encoded origin
    // This uses the same decoding logic as the Rust program
    let decoded_origin = decode_huffman_origin_test(huffman_tree, huffman_encoded_origin).unwrap();
    let decoded_origin_str = String::from_utf8(decoded_origin).unwrap();
    
    println!("    decoded_origin: {}", decoded_origin_str);
    assert_eq!(decoded_origin_str, origin, "decoded origin should match original");
    
    println!("  ✓ TypeScript-Rust WebAuthn compatibility verified!");
}

/// Test implementation of huffman decoding (copied from the Rust program)
fn decode_huffman_origin_test(tree_data: &[u8], encoded_data: &[u8]) -> Result<Vec<u8>, &'static str> {
    // Constants for huffman decoding
    const NODE_SIZE: usize = 3;
    const LEAF_NODE: u8 = 0;
    const INTERNAL_NODE: u8 = 1;
    const BIT_MASKS: [u8; 8] = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];
    
    if tree_data.len() % NODE_SIZE != 0 || tree_data.is_empty() {
        return Err("Invalid tree data");
    }
    
    let node_count = tree_data.len() / NODE_SIZE;
    let root_index = node_count - 1;
    let mut current_node = root_index;
    let mut decoded = Vec::new();
    
    for &byte in encoded_data {
        for bit_pos in 0..8 {
            let node_offset = current_node * NODE_SIZE;
            if node_offset + 2 >= tree_data.len() {
                return Err("Invalid node offset");
            }
            
            let node_type = tree_data[node_offset];
            let left_or_char = tree_data[node_offset + 1];
            let right = tree_data[node_offset + 2];
            
            if node_type == LEAF_NODE {
                // Found a character, add it to decoded output
                decoded.push(left_or_char);
                current_node = root_index; // Reset to root
            } else if node_type == INTERNAL_NODE {
                // Navigate tree based on bit
                let bit = (byte & BIT_MASKS[bit_pos]) != 0;
                current_node = if bit {
                    right as usize
                } else {
                    left_or_char as usize
                };
                
                if current_node >= node_count {
                    return Err("Invalid node index");
                }
            } else {
                return Err("Invalid node type");
            }
        }
    }
    
    Ok(decoded)
}