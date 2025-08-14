//! Constants used throughout the state crate.
//!
//! This module defines various constant values used by the Swig wallet system.

/// Size in bytes of a program scope data structure.
/// This is used for memory allocation and validation when handling program
/// scope actions.
pub const PROGRAM_SCOPE_BYTE_SIZE: usize = 144;

/// Size in bytes of an external kill switch data structure.
/// This is used for memory allocation and validation when handling external
/// kill switch actions.
pub const EXTERNAL_KILL_SWITCH_BYTE_SIZE: usize = 80;
