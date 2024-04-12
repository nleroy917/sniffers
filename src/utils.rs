use std::io::Read;
use ring::digest::{Context, Digest, SHA256};

use anyhow::Result;

pub fn normalize_path(input: &str) -> String {
    if input.ends_with('/') || input == "." {
        format!("{input}/**/*")
    } else if input.contains('*') {
        input.to_string()
    } else {
        format!("{input}/**/*")
    }
}

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