use std::io::stdout;
use std::io::Write;

use anyhow::Context;
use anyhow::Result;
use clap::{arg, Command};

use sniffers::Sniffer;

pub mod consts {
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");
    pub const PKG_NAME: &str = env!("CARGO_PKG_NAME");
    pub const BIN_NAME: &str = env!("CARGO_PKG_NAME");
    pub const SNIFF_CMD: &str = "sniff";
    pub const INDEX_CMD: &str = "index";
    pub const DEFAULT_PATH: &str = ".";
}

fn build_sniff_cli() -> Command {
    Command::new(consts::SNIFF_CMD)
        .author("Nathan LeRoy")
        .about("Run the sniff to detect any changed files.")
        .arg(arg!(<path> "Path to files to sniff").required(false))
}

fn build_index_cli() -> Command {
    Command::new(consts::INDEX_CMD)
        .author("Nathan LeRoy")
        .about("Index the specified directory or path.")
        .arg(arg!(<path> "Path to files to index").required(false))
}

fn build_parser() -> Command {
    Command::new(consts::BIN_NAME)
        .bin_name(consts::BIN_NAME)
        .version(consts::VERSION)
        .author("Nathan LeRoy")
        .about("A command line tool that sniffs for any file changes in specified directories.")
        .subcommand_required(true)
        .subcommand(build_sniff_cli())
        .subcommand(build_index_cli())
}

fn main() -> Result<()> {
    let app = build_parser();
    let matches = app.get_matches();

    // build handler for stdout
    let stdout = stdout();
    let mut handle = stdout.lock();

    match matches.subcommand() {
        Some((consts::SNIFF_CMD, matches)) => {
            let default_path = consts::DEFAULT_PATH.to_string();
            let path = matches
                .get_one::<String>("path")
                .unwrap_or(&default_path);

            let sniffer = Sniffer::default().path(path);

            sniffer.sniff().with_context(|| {
                "Could not sniff files"
            })?;

            handle.write_all("Done sniffing!\n".as_bytes())?;
            
        },

        Some((consts::INDEX_CMD, matches)) => {
            let default_path = consts::DEFAULT_PATH.to_string();
            let path = matches
                .get_one::<String>("path")
                .unwrap_or(&default_path);

            let sniffer = Sniffer::default().path(path);

            sniffer.index().with_context(|| {
                "There was an error running the index."
            })?;

            handle.write_all("Done sniffing!\n".as_bytes())?;
        }

        _ => unreachable!("Something went wrong!"),
    }

    



    Ok(())
}
