mod base64;
mod csv;
mod genpass;
mod http;
mod text;

use self::{csv::CsvOpts, genpass::GenPassOpts};
use clap::Parser;
use std::path::{self, Path, PathBuf};

pub use self::{
    base64::{Base64Format, Base64SubCommand},
    csv::OutputFormat,
    http::HttpSubCommand,
    text::{TextSignFormat, TextSubCommand},
};

#[derive(Debug, Parser)]
#[command(name = "rcli", version, author, about, long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, Parser)]
pub enum SubCommand {
    #[command(name = "csv", about = "Show CSV, or convert CSV to other formats.")]
    Csv(CsvOpts),
    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),
    #[command(subcommand, about = "Base64 encode or decode")]
    Base64(Base64SubCommand),
    #[command(
        subcommand,
        about = "generate a signature with symmetric/asymmetric encryption, or verify signature"
    )]
    Text(TextSubCommand),
    #[command(subcommand, about = "generate a http server")]
    Http(HttpSubCommand),
}

fn verify_file(file: &str) -> Result<String, &'static str> {
    // if input is "-" or file exists
    if file == "-" || path::Path::new(file).exists() {
        Ok(file.into()) // 切片 -> 含有所有权的String
    } else {
        Err("File does not exist")
    }
}

fn verify_path(path: &str) -> Result<PathBuf, &'static str> {
    // if path exists and is a directory
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(p.into())
    } else {
        Err("Path does not exist or is not a directory")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_file() {
        assert_eq!(verify_file("-"), Ok("-".into()));
        assert_eq!(verify_file("*"), Err("File does not exist"));
        assert_eq!(verify_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(verify_file("not-exist"), Err("File does not exist"));
    }
}
