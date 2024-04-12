use anyhow::{Context, Result};
use glob::glob;
use data_encoding::HEXUPPER;
use std::io::{BufReader, Write};
use std::fmt::Display;
use std::path::PathBuf;
use std::fs::File;

use crate::consts::{HASH_STORE_FILE, DELIMITER};
use crate::utils::{normalize_path, hash_file};

pub struct Sniffer {
    path: PathBuf,
    hash_store_file: PathBuf,
}

impl Sniffer {
    pub fn new() -> Sniffer {
        Sniffer {
            path: PathBuf::new(),
            hash_store_file: PathBuf::new(),
        }
    }

    pub fn path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.path = path.into();
        self
    }

    pub fn hash_store_file(mut self, file: PathBuf) -> Self {
        self.hash_store_file = file;
        self
    }

    pub fn index(&self) -> Result<()> {
        let mut hash_store_file = File::create(&self.hash_store_file)
            .with_context(|| "Could not read create the hash store file.")?;

        let path = normalize_path(self.path.to_str().unwrap());

        let files = glob(&path).with_context(|| "Could not read files from path.")?;

        for file in files {
            let file = file?;
            
            // skip directories
            if file.is_dir() {
                continue;
            }

            let reader = BufReader::new(File::open(&file)?);
            let hash = hash_file(reader)?;
            
            hash_store_file.write_all(file.to_str().unwrap().as_bytes())?;
            hash_store_file.write_all(DELIMITER.as_bytes())?;
            hash_store_file.write_all(HEXUPPER.encode(hash.as_ref()).as_bytes())?;
            hash_store_file.write_all("\n".as_bytes())?;
        }

        Ok(())
    }

    pub fn sniff(&self) -> Result<()> {

        let _hash_store_file = File::open(&self.hash_store_file)
            .with_context(|| "Could not locate the hash file. have you run `index`?")?;

        let path = normalize_path(self.path.to_str().unwrap());

        let files = glob(&path).with_context(|| "Could not read files from path.")?;

        for file in files {
            let file = file?;
            
            // skip directories
            if file.is_dir() {
                continue;
            }

            let reader = BufReader::new(File::open(&file)?);
            let _hash = hash_file(reader)?;
        }

        Ok(())
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
