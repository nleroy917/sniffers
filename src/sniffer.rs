//! 
//! # Sniffer
//! Core sniffer struct that implements the logic for detecting file changes.
//! 
//! ## Usage
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

use anyhow::{Context, Result};
use data_encoding::HEXUPPER;
use glob::glob;
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::consts::{DELIMITER, HASH_STORE_FILE};
use crate::utils::{hash_file, normalize_path};

pub struct Sniffer {
    path: PathBuf,
    hash_store_file: PathBuf,
}

impl Sniffer {
    ///
    /// Create a new Sniffer instance. This creates a blank Sniffer instance with no path or hash store file.
    pub fn new() -> Sniffer {
        Sniffer {
            path: PathBuf::new(),
            hash_store_file: PathBuf::new(),
        }
    }

    ///
    /// Set the path to sniff. This sets the path to sniff for file changes.
    /// 
    /// # Arguments
    /// - `path` - The path to sniff for file changes.
    /// 
    pub fn path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.path = path.into();
        self
    }

    ///
    /// Set the hash store file. This sets the file to store the hashes of the files in the path.
    /// 
    /// # Arguments
    /// - `file` - The file to store the hashes of the files in the path.
    /// 
    pub fn hash_store_file(mut self, file: PathBuf) -> Self {
        self.hash_store_file = file;
        self
    }

    ///
    /// Index the files in the path. This hashes the files in the path and stores the hashes in the hash store file.
    /// 
    /// # Returns
    /// A `Result` with the success or failure of the operation.
    /// 
    pub fn index(&self) -> Result<()> {
        let mut hash_store_file = File::create(&self.hash_store_file)
            .with_context(|| "Could not read create the hash store file.")?;

        let path = normalize_path(self.path.to_str().unwrap());

        let files = glob(&path).with_context(|| "Could not read files from path.")?;

        for file in files {
            let file = file?;
            let absolute_path = file.canonicalize()?;

            // skip directories
            if file.is_dir() {
                continue;
            }

            let reader = BufReader::new(File::open(&file)?);
            let hash = hash_file(reader)?;

            // write to the file... {file path} {}\n
            hash_store_file.write_all(absolute_path.to_str().unwrap().as_bytes())?;
            hash_store_file.write_all(DELIMITER.as_bytes())?;
            hash_store_file.write_all(HEXUPPER.encode(hash.as_ref()).as_bytes())?;
            hash_store_file.write_all("\n".as_bytes())?;
        }

        Ok(())
    }

    ///
    /// Sniff the files in the path. This compares the hashes of the files in the path with the hashes stored in the hash store file.
    /// 
    /// # Returns
    /// A `Result` with the list of altered files.
    pub fn sniff(&self) -> Result<Vec<String>> {

        let mut altered_files: Vec<String> = Vec::new();

        let hash_store_file = File::open(&self.hash_store_file)
            .with_context(|| "Could not locate the hash file. have you run `index`?")?;

        let mut hash_store: HashMap<String, String> = HashMap::new();

        let hash_store_reader = BufReader::new(hash_store_file);

        // populate an in-memory representation of the hash file store
        for line in hash_store_reader.lines() {
            let line = line?;
            let entries = line.rsplit_once(DELIMITER);

            if entries.is_none() {
                anyhow::bail!("Unexpected hashfile entry found for line {line}")
            }

            let entries = entries.unwrap();
            let file_name = entries.0;
            let hash = entries.1;

            hash_store.insert(file_name.to_string(), hash.to_string());
        }

        let path = normalize_path(self.path.to_str().unwrap());

        let files = glob(&path).with_context(|| "Could not read files from path.")?;

        // get hashes of all files in specified path, update in-memory representation
        for file in files {
            let file = file?;
            let absolute_path = file.canonicalize()?;
            let absolute_path = absolute_path.to_str().unwrap().to_string();

            // skip directories
            if file.is_dir() {
                continue;
            }

            let reader = BufReader::new(File::open(&file)?);
            let hash = hash_file(reader)?;
            let new_hash = HEXUPPER.encode(hash.as_ref());

            let old_hash = hash_store.entry(absolute_path.clone()).or_insert_with(|| {
                altered_files.push(absolute_path.clone());
                new_hash.clone()
            });

            if (*old_hash != new_hash) && !absolute_path.ends_with(self.hash_store_file.to_str().unwrap()) {
                // update the hash in the in-memory representation
                *old_hash = new_hash;
                altered_files.push(absolute_path);
            }

            // else -- do nothing!
        }

        // dump in-memory representation back to the hash store file.
        let mut hash_store_file = File::create(&self.hash_store_file)
            .with_context(|| "Could not read create the hash store file.")?;

        for (file, hash) in hash_store.iter() {
            hash_store_file.write_all(file.as_bytes())?;
            hash_store_file.write_all(DELIMITER.as_bytes())?;
            hash_store_file.write_all(hash.as_bytes())?;
            hash_store_file.write_all("\n".as_bytes())?;
        }

        Ok(altered_files)
    }
}

impl Default for Sniffer {
    fn default() -> Self {
        Sniffer {
            path: PathBuf::new(),
            hash_store_file: PathBuf::from(HASH_STORE_FILE),
        }
    }
}

impl Display for Sniffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // format and display as a struct
        write!(
            f,
            "Sniffer {{ path: {:?}, hash_store_file: {:?} }}",
            self.path, self.hash_store_file
        )
    }
}
