use anyhow::{ensure, Context, Result};
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

    pub fn sniff(&self) -> Result<Vec<String>> {

        let mut altered_files: Vec<String> = Vec::new();

        let hash_store_file = File::open(&self.hash_store_file)
            .with_context(|| "Could not locate the hash file. have you run `index`?")?;

        let mut hash_store: HashMap<String, String> = HashMap::new();

        let hash_store_reader = BufReader::new(hash_store_file);

        // populate an in-memory representation of the hash file store
        for line in hash_store_reader.lines() {
            let line = line?;
            let entries = line.split(DELIMITER).collect::<Vec<_>>();

            // check integrity of the entry
            ensure!(
                entries.len() == 2,
                format!("Unexpected hashfile entry found for line {line}")
            );

            let file_name = entries[0];
            let hash = entries[1];

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

            if *old_hash != new_hash {
                // update the hash in the in-memory representation
                *old_hash = new_hash;
                altered_files.push(absolute_path);
            }

            // else -- do nothing!
        }

        // dump in-memory representation back to the hash store file.

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
