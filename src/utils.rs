///
/// Utility functions for the application.
/// 
use ring::digest::{Context, Digest, SHA256};
use std::io::Read;

use anyhow::Result;

///
/// Normalize a path. This normalizes a path to a glob pattern.
/// 
/// # Arguments
/// - `input` - The path to normalize.
/// 
/// # Returns
/// The normalized path.
pub fn normalize_path(input: &str) -> String {
    if input.ends_with('/') || input == "." {
        format!("{input}/**/*")
    } else if input.contains('*') {
        input.to_string()
    } else {
        format!("{input}/**/*")
    }
}

///
/// Hash a file. This hashes a file using the SHA256 algorithm.
/// 
/// # Arguments
/// - `reader` - The reader to read the file.
/// 
/// # Returns
/// The hash of the file.
pub fn hash_file<R: Read>(mut reader: R) -> Result<Digest> {
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}
