//! Constants used throughout the State-X crate.
//!
//! This module defines various constant values used by the Swig wallet system.

/// Size in bytes of a program scope data structure.
/// This is used for memory allocation and validation when handling program
/// scope actions.
pub const PROGRAM_SCOPE_BYTE_SIZE: usize = 144;

/// Size in bytes of an authorization lock data structure.
/// This is used for memory allocation and validation when handling
/// authorization lock actions.
pub const AUTHORIZATION_LOCK_BYTE_SIZE: usize = 56;
