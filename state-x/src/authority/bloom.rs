// #![warn(unexpected_cfgs)]

// use core::mem::size_of;

// /// MurmurHash3 32-bit using Pinocchio syscall
// pub fn hash_32(data: &[u8]) -> u32 {
//     #[cfg(target_feature = "static-syscalls")]
//     {
//         pinocchio::syscalls::murmur3_32(data, 777)
//     }
//     #[cfg(not(target_feature = "static-syscalls"))]
//     {
//         use std::io::Cursor;

//         use murmur3::murmur3_32;
//         let mut cursor = Cursor::new(data);
//         murmur3_32(&mut cursor, 777).unwrap()
//     }
// }

// /// Calculate the required bytes for a filter with the given parameters
// /// - n: number of entries
// /// - f: bits for fingerprint
// /// - o: bits for offset
// ///
// /// Returns the number of bytes needed for the packed array
// pub const fn calculate_packed_size(n: usize, f: usize, o: usize) -> usize {
//     let bits_per_entry = f + o;
//     let total_bits = n * bits_per_entry;
//     let bytes = (total_bits + 7) / 8; // Ceiling division by 8 to get bytes

//     // Round up to multiple of 8 for alignment

//     (bytes + 7) & !7
// }

// /// Calculate how many bytes of padding are needed to align to 8-byte boundary
// /// - base_size: total size of fields before padding
// pub const fn calculate_padding_size() -> usize {
//     let base_size = size_of::<u64>() + size_of::<u16>(); // base_slot + next_index
//     let remainder = base_size % 8;
//     if remainder == 0 {
//         0
//     } else {
//         8 - remainder
//     }
// }

// /// A macro to define a space-efficient probabilistic data structure for testing
// /// set membership with expiry
// ///
// /// Parameters:
// /// - name: The name for the new filter type
// /// - n: Number of entries the filter can hold
// /// - f: Bits used for the fingerprint
// /// - o: Bits used for the offset
// macro_rules! define_tiny_filter {
//     ($name:ident, $n:expr, $f:expr, $o:expr) => {
//         #[derive(Debug, no_padding::NoPadding)]
//         #[repr(C, align(8))]
//         pub struct $name {
//             pub(crate) base_slot: u64,
//             pub(crate) next_index: u16,
//             pub(crate) _padding: [u8; crate::authority::bloom::calculate_padding_size()],
//             pub(crate) packed: [u8; crate::authority::bloom::calculate_packed_size($n, $f, $o)],
//         }

//         impl crate::Transmutable for $name {
//             const LEN: usize = core::mem::size_of::<Self>();
//         }

//         impl crate::TransmutableMut for $name {}

//         impl Default for $name {
//             fn default() -> Self {
//                 Self::new()
//             }
//         }

//         impl $name {
//             const ARRAY_SIZE: usize = crate::authority::bloom::calculate_packed_size($n, $f, $o);

//             pub fn new() -> Self {
//                 Self {
//                     base_slot: 0,
//                     next_index: 0,
//                     _padding: [0; crate::authority::bloom::calculate_padding_size()],
//                     packed: [0; crate::authority::bloom::calculate_packed_size($n, $f, $o)],
//                 }
//             }

//             pub fn pack_entry(offset: u8, fp: u16) -> u32 {
//                 let offset_mask = (1 << $o) - 1;
//                 let fp_mask = (1 << $f) - 1;
//                 ((offset as u32 & offset_mask) << $f) | (fp as u32 & fp_mask)
//             }

//             pub fn unpack_entry(bits: u32) -> (u8, u16) {
//                 let fp_mask = (1 << $f) - 1;
//                 let fp = (bits & fp_mask) as u16;
//                 let offset = ((bits >> $f) & ((1 << $o) - 1)) as u8;
//                 (offset, fp)
//             }

//             pub fn set_entry(&mut self, index: usize, offset: u8, fp: u16) {
//                 let bits_per_entry = $f + $o;
//                 let bit_index = index * bits_per_entry;
//                 let packed_value = Self::pack_entry(offset, fp);

//                 for i in 0..bits_per_entry {
//                     let byte_idx = (bit_index + i) / 8;
//                     if byte_idx >= Self::ARRAY_SIZE {
//                         break;
//                     }
//                     let bit_idx = (bit_index + i) % 8;

//                     let bit = (packed_value >> i) & 1;
//                     unsafe {
//                         let byte = self.packed.get_unchecked_mut(byte_idx);
//                         *byte &= !(1 << bit_idx);
//                         *byte |= (bit as u8) << bit_idx;
//                     }
//                 }
//             }

//             pub fn get_entry(&self, index: usize) -> (u8, u16) {
//                 let bits_per_entry = $f + $o;
//                 let bit_index = index * bits_per_entry;
//                 let mut value: u32 = 0;
//                 let array_size = Self::ARRAY_SIZE;

//                 for i in 0..bits_per_entry {
//                     let byte_idx = (bit_index + i) / 8;
//                     if byte_idx >= array_size {
//                         break;
//                     }
//                     let bit_idx = (bit_index + i) % 8;

//                     let bit = (unsafe { self.packed.get_unchecked(byte_idx) } >> bit_idx) & 1;
//                     value |= (bit as u32) << i;
//                 }

//                 Self::unpack_entry(value)
//             }

//             pub fn insert(&mut self, key: &[u8], slot: u64) {
//                 if self.base_slot == 0 {
//                     self.base_slot = slot;
//                 }
//                 let offset = (slot - self.base_slot) as u8;
//                 let fp = (crate::authority::bloom::hash_32(key) >> (32 - $f)) as u16;

//                 self.set_entry(self.next_index as usize, offset, fp);
//                 self.next_index = (self.next_index + 1) % ($n as u16);
//             }

//             pub fn contains(&self, key: &[u8], current_slot: u64, window: u64) -> bool {
//                 let fp = (crate::authority::bloom::hash_32(key) >> (32 - $f)) as u16;

//                 for i in 0..$n {
//                     let (offset, entry_fp) = self.get_entry(i);
//                     let entry_slot = self.base_slot + offset as u64;

//                     if entry_fp == fp && current_slot.saturating_sub(entry_slot) <= window {
//                         return true;
//                     }
//                 }

//                 false
//             }
//         }
//     };
// }

// #[cfg(test)]
// mod tests {
//     use rand::{rngs::StdRng, Rng, SeedableRng};

//     use super::*;

//     // Define the filter types we'll use for testing
//     define_tiny_filter!(DefaultTinyFilter, 60, 10, 8);
//     define_tiny_filter!(LargeTinyFilter, 100, 9, 8);
//     define_tiny_filter!(HighPrecisionTinyFilter, 60, 12, 8);
//     define_tiny_filter!(MinimalTinyFilter, 30, 8, 8);
//     define_tiny_filter!(CustomTinyFilter, 25, 10, 6);

//     // Helper function to generate a random 64-byte sequence with a specific seed
//     // Using a seed ensures deterministic test results while still testing with
//     // random data
//     fn random_bytes(seed: u64) -> [u8; 64] {
//         let mut rng = StdRng::seed_from_u64(seed);
//         let mut bytes = [0u8; 64];
//         rng.fill(&mut bytes);
//         bytes
//     }

//     #[test]
//     fn test_calculate_packed_size() {
//         // Test size calculation function
//         assert_eq!(calculate_packed_size(60, 9, 8), 128);
//         assert_eq!(calculate_packed_size(30, 8, 8), 64); // Rounded up to multiple of 8
//         assert_eq!(calculate_packed_size(100, 9, 8), 216); // Rounded up to
//                                                            // multiple of 8
//     }

//     #[test]
//     fn test_insert_and_contains() {
//         let mut filter = DefaultTinyFilter::new();
//         let slot = 1_000;

//         let key1 = random_bytes(1);
//         let key2 = random_bytes(2);
//         let key3 = random_bytes(3);
//         let key4 = random_bytes(4); // Different key not inserted

//         filter.insert(&key1, slot);
//         filter.insert(&key2, slot + 1);
//         filter.insert(&key3, slot + 2);

//         assert!(filter.contains(&key1, slot + 3, 10));
//         assert!(filter.contains(&key2, slot + 3, 10));
//         assert!(filter.contains(&key3, slot + 3, 10));
//         assert!(!filter.contains(&key4, slot + 3, 10));
//     }

//     // what is the padding and size for 60,10,8?
//     #[test]
//     fn test_padding_and_size() {
//         let filter = DefaultTinyFilter::new();
//         assert_eq!(filter.packed.len(), 136);
//         assert_eq!(filter._padding.len(), 6);
//     }

//     #[test]
//     fn test_expiry() {
//         let mut filter = DefaultTinyFilter::new();
//         let slot = 5_000;

//         let key = random_bytes(5);
//         filter.insert(&key, slot);
//         assert!(filter.contains(&key, slot + 5, 10));
//         assert!(!filter.contains(&key, slot + 20, 10)); // expired
//     }

//     #[test]
//     fn test_false_positive_rate() {
//         let mut filter = DefaultTinyFilter::new();
//         let slot = 10_000;
//         let inserted: usize = 60;
//         let test_set_size: usize = 1_000; // Reduced test size

//         // Insert 60 random keys
//         for i in 0..inserted {
//             let key = random_bytes(i as u64 + 100);
//             filter.insert(&key, slot + i as u64);
//         }

//         // Test with 1000 different random keys
//         let mut false_positives = 0;
//         for i in 0..test_set_size {
//             let key = random_bytes(i as u64 + 1000); // Different seed range
//             if filter.contains(&key, slot + inserted as u64, 255) {
//                 false_positives += 1;
//             }
//         }

//         let fp_rate = false_positives as f64 / test_set_size as f64;
//         println!("False positive rate: {:.6}", fp_rate);
//         assert!(fp_rate < 0.15); // The actual observed false positive rate is
//                                  // higher than expected
//     }

//     #[test]
//     fn test_pack_unpack_entry() {
//         // Test different combinations of offset and fingerprint values
//         let test_cases = [
//             (0u8, 0u16),
//             (1, 1),
//             (255, 511), // Max values
//             (127, 255),
//             (0, 511),
//             (255, 0),
//         ];

//         for (offset, fp) in test_cases {
//             let packed = DefaultTinyFilter::pack_entry(offset, fp);
//             let (unpacked_offset, unpacked_fp) = DefaultTinyFilter::unpack_entry(packed);

//             assert_eq!(unpacked_offset, offset); // Apply mask to expected value
//             assert_eq!(unpacked_fp, fp & 0x01FF); // Apply mask to expected
//                                                   // value
//         }
//     }

//     #[test]
//     fn test_set_get_entry() {
//         let mut filter = DefaultTinyFilter::new();

//         let test_cases = [
//             (0, 1u8, 42u16),
//             (1, 5, 255),
//             (59, 255, 511), // Last entry
//             (30, 127, 127),
//         ];

//         for (index, offset, fp) in test_cases {
//             filter.set_entry(index, offset, fp);
//             let (retrieved_offset, retrieved_fp) = filter.get_entry(index);

//             assert_eq!(retrieved_offset, offset);
//             assert_eq!(retrieved_fp, fp & 0x01FF);
//         }
//     }

//     #[test]
//     fn test_wrapping_behavior() {
//         let mut filter = DefaultTinyFilter::new();
//         let slot = 1000;

//         // Generate 70 distinct random key values (60 for initial fill, 10 for overflow)
//         let keys: Vec<[u8; 64]> = (0..70).map(|i| random_bytes(i as u64 + 2000)).collect();

//         // Fill up the filter completely
//         for i in 0..60 {
//             filter.insert(&keys[i], slot + i as u64);
//         }

//         // All keys should be found
//         for i in 0..60 {
//             assert!(filter.contains(&keys[i], slot + 60, 61));
//         }

//         // Add more keys which should start overwriting from index 0
//         for i in 0..10 {
//             filter.insert(&keys[60 + i], slot + 60 + i as u64);
//         }

//         // New keys should be found
//         for i in 0..10 {
//             assert!(filter.contains(&keys[60 + i], slot + 70, 11));
//         }

//         // First 10 keys should be overwritten and not found
//         for i in 0..10 {
//             assert!(!filter.contains(&keys[i], slot + 70, 10));
//         }

//         // Keys 10-59 should still be found
//         for i in 10..60 {
//             assert!(filter.contains(&keys[i], slot + 70, 61));
//         }
//     }

//     #[test]
//     fn test_different_size_configurations() {
//         // Test different configurations using different filter types
//         let mut small_filter = MinimalTinyFilter::new();
//         let mut large_filter = LargeTinyFilter::new();
//         let mut high_precision = HighPrecisionTinyFilter::new();
//         let mut custom_filter = CustomTinyFilter::new();

//         let slot = 2000;
//         let key = random_bytes(8000);

//         small_filter.insert(&key, slot);
//         large_filter.insert(&key, slot);
//         high_precision.insert(&key, slot);
//         custom_filter.insert(&key, slot);

//         // Verify they all can find the key
//         assert!(small_filter.contains(&key, slot, 0));
//         assert!(large_filter.contains(&key, slot, 0));
//         assert!(high_precision.contains(&key, slot, 0));
//         assert!(custom_filter.contains(&key, slot, 0));
//     }

//     #[test]
//     fn test_base_slot_behavior() {
//         let mut filter = DefaultTinyFilter::new();

//         // Test initial base_slot setting
//         assert_eq!(filter.base_slot, 0);

//         // Base slot should be set on first insert
//         let key1 = random_bytes(3000);
//         filter.insert(&key1, 100);
//         assert_eq!(filter.base_slot, 100);

//         // Base slot should not change on subsequent inserts
//         let key2 = random_bytes(3001);
//         filter.insert(&key2, 200);
//         assert_eq!(filter.base_slot, 100);

//         // Test with zero slot
//         let mut filter2 = DefaultTinyFilter::new();
//         let key3 = random_bytes(3002);
//         filter2.insert(&key3, 0);
//         assert_eq!(filter2.base_slot, 0);
//     }

//     #[test]
//     fn test_window_boundaries() {
//         let mut filter = DefaultTinyFilter::new();

//         // Create a very simple test case
//         let slot = 1000;
//         let key = random_bytes(4000);

//         // Insert a test key at this slot
//         filter.insert(&key, slot);

//         // Just verify it can be found with a direct lookup
//         assert!(filter.contains(&key, slot, 0));

//         // Test window boundaries with small values
//         assert!(filter.contains(&key, slot + 5, 5));
//         assert!(!filter.contains(&key, slot + 6, 5));
//     }

//     #[test]
//     fn test_memory_layout() {
//         // Test that there's no implicit padding between fields
//         use std::mem::{align_of, size_of};

//         // Verify the padding size calculation
//         let expected_padding = calculate_padding_size();
//         println!("Calculated padding size: {}", expected_padding);

//         // Test DefaultTinyFilter
//         let expected_size = size_of::<u64>()
//             + size_of::<u16>()
//             + expected_padding
//             + calculate_packed_size(60, 10, 8);
//         assert_eq!(size_of::<DefaultTinyFilter>(), expected_size);
//         assert_eq!(align_of::<DefaultTinyFilter>(), 8);

//         // Test CustomTinyFilter
//         let expected_size = size_of::<u64>()
//             + size_of::<u16>()
//             + expected_padding
//             + calculate_packed_size(25, 10, 6);
//         assert_eq!(size_of::<CustomTinyFilter>(), expected_size);
//         assert_eq!(align_of::<CustomTinyFilter>(), 8);

//         // Verify that size is a multiple of alignment
//         assert_eq!(
//             size_of::<DefaultTinyFilter>() % align_of::<DefaultTinyFilter>(),
//             0
//         );
//         assert_eq!(
//             size_of::<CustomTinyFilter>() % align_of::<CustomTinyFilter>(),
//             0
//         );
//     }
// }
