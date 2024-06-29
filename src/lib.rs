//! # sniffers
//! 
//! `sniffers` is a simple library for detecting file changes. This library contains 
//! a library and a binary. The library is used to detect file changes in a directory,
//! and the binary is used to detect file changes in a directory and run a command when 
//! a change is detected.
//! 
//! ## Library
//! 
//! The library contains the core logic for detecting file changes.
//! 
//! ### Usage
//! ```rust
//! use sniffers::Sniffer;
//! 
//! let sniffer = Sniffer::default();
//! 
//! sniffer.index();
//! 
//! let altered_files = sniffer.sniff();
//! 
//! println!("{:?}", altered_files);
//! ```
//! 
//! ## Binary
//! 
//! The binary wraps the library and provides a command line interface for detecting file changes.
//! 
//! ### Usage
//! 
//! ```bash
//! sniffers index
//! sniffers sniff
//! ```

pub mod consts;
pub mod sniffer;
pub mod utils;

pub use sniffer::Sniffer;