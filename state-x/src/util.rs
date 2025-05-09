
/// Macro for reading numeric fields from byte arrays with appropriate
/// validation.
///
/// This macro handles reading different integer types (u8, u32, u64, u128) from
/// raw byte arrays with proper size validation and byte order assembly. It uses
/// unchecked access for performance in verified contexts.
///
/// # Arguments
/// * `$data` - The source byte array to read from
/// * `$start` - Starting position in the byte array
/// * `$end` - Ending position in the byte array
/// * `$type` - The Rust type to interpret the bytes as (u8, u32, u64, u128)
/// * `$width` - Expected width in bytes (1, 4, 8, or 16) for the numeric type
///
/// # Returns
/// * `Result<u128, ProgramError>` - The numeric value converted to u128 or an
///   error
///
/// # Safety
/// This macro uses unchecked memory access and assumes the caller has verified
/// that `$data` has enough bytes to read from the given range.
#[macro_export]
macro_rules! read_numeric_field {
    ($data:expr, $start:expr, $end:expr, $type:ty, $width:expr, $error:expr) => {{
        if $end - $start != $width {
            return Err($error);
        }

        if $width == 1 {
            Ok((*$data.get_unchecked($start) as $type) as u128)
        } else if $width == 4 {
            let d0 = *$data.get_unchecked($start);
            let d1 = *$data.get_unchecked($start + 1);
            let d2 = *$data.get_unchecked($start + 2);
            let d3 = *$data.get_unchecked($start + 3);

            let val = (d0 as $type)
                | ((d1 as $type) << 8)
                | ((d2 as $type) << 16)
                | ((d3 as $type) << 24);
            Ok(val as u128)
        } else if $width == 8 {
            let d0 = *$data.get_unchecked($start);
            let d1 = *$data.get_unchecked($start + 1);
            let d2 = *$data.get_unchecked($start + 2);
            let d3 = *$data.get_unchecked($start + 3);
            let d4 = *$data.get_unchecked($start + 4);
            let d5 = *$data.get_unchecked($start + 5);
            let d6 = *$data.get_unchecked($start + 6);
            let d7 = *$data.get_unchecked($start + 7);

            let val = (d0 as $type)
                | ((d1 as $type) << 8)
                | ((d2 as $type) << 16)
                | ((d3 as $type) << 24)
                | ((d4 as $type) << 32)
                | ((d5 as $type) << 40)
                | ((d6 as $type) << 48)
                | ((d7 as $type) << 56);
            Ok(val as u128)
        } else if $width == 16 {
            let d0 = *$data.get_unchecked($start);
            let d1 = *$data.get_unchecked($start + 1);
            let d2 = *$data.get_unchecked($start + 2);
            let d3 = *$data.get_unchecked($start + 3);
            let d4 = *$data.get_unchecked($start + 4);
            let d5 = *$data.get_unchecked($start + 5);
            let d6 = *$data.get_unchecked($start + 6);
            let d7 = *$data.get_unchecked($start + 7);
            let d8 = *$data.get_unchecked($start + 8);
            let d9 = *$data.get_unchecked($start + 9);
            let d10 = *$data.get_unchecked($start + 10);
            let d11 = *$data.get_unchecked($start + 11);
            let d12 = *$data.get_unchecked($start + 12);
            let d13 = *$data.get_unchecked($start + 13);
            let d14 = *$data.get_unchecked($start + 14);
            let d15 = *$data.get_unchecked($start + 15);

            let val = (d0 as $type)
                | ((d1 as $type) << 8)
                | ((d2 as $type) << 16)
                | ((d3 as $type) << 24)
                | ((d4 as $type) << 32)
                | ((d5 as $type) << 40)
                | ((d6 as $type) << 48)
                | ((d7 as $type) << 56)
                | ((d8 as $type) << 64)
                | ((d9 as $type) << 72)
                | ((d10 as $type) << 80)
                | ((d11 as $type) << 88)
                | ((d12 as $type) << 96)
                | ((d13 as $type) << 104)
                | ((d14 as $type) << 112)
                | ((d15 as $type) << 120);
            Ok(val as u128)
        } else {
            Err($error)
        }
    }};
}
