use super::{verify_file, verify_path};
use crate::{
    get_content, get_reader, process_text_decrypt, process_text_encrypt, process_text_key_generate,
    process_text_sign, process_text_verify, CmdExecutor,
};
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use std::{fs, path::PathBuf, str::FromStr};

#[derive(Debug, Parser)]
pub enum TextSubCommand {
    // private key为非对称加密的私钥 session key为对称加密的密钥
    #[command(about = "sign a text with a private/session key and return a signature")]
    Sign(TextSignOpts),
    #[command(about = "verify a signature with a public/session key")]
    Verify(TextVerifyOpts),
    #[command(about = "generate a random blake3 key or ed25519 key pair")]
    Generate(KeyGenerateOpts),
    #[command(about = "encrypt a plain text with a key")]
    Encrypt(TextEncryptOpts),
    #[command(about = "decrypt a cipher text with a key")]
    Decrypt(TextDecryptOpts),
}
/// 生成文本签名
#[derive(Debug, Parser)]
pub struct TextSignOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(long, value_parser = parse_text_sign_format, default_value = "blake3")]
    pub format: TextSignFormat,
}
/// 验证文本签名
#[derive(Debug, Parser)]
pub struct TextVerifyOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(long)]
    pub sig: String,
    #[arg(long, value_parser = parse_text_sign_format, default_value = "blake3")]
    pub format: TextSignFormat,
}
/// 生成签名密钥
#[derive(Debug, Parser)]
pub struct KeyGenerateOpts {
    #[arg(long, value_parser = parse_text_sign_format, default_value = "blake3")]
    pub format: TextSignFormat,
    #[arg(short, long, value_parser = verify_path)]
    pub output_path: PathBuf,
}

#[derive(Debug, Parser)]
pub struct TextEncryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(long, value_parser = parse_text_sign_format, default_value = "chacha20poly1305")]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct TextDecryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(long, value_parser = parse_text_sign_format, default_value = "chacha20poly1305")]
    pub format: TextSignFormat,
}

#[derive(Debug, Clone, Copy)]
pub enum TextSignFormat {
    Blake3,
    Ed25519,
    Chacha20Poly1305,
}

fn parse_text_sign_format(format: &str) -> Result<TextSignFormat> {
    format.parse()
}

impl FromStr for TextSignFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(TextSignFormat::Blake3),
            "ed25519" => Ok(TextSignFormat::Ed25519),
            "chacha20poly1305" => Ok(TextSignFormat::Chacha20Poly1305),
            _ => Err(anyhow::anyhow!("invalid format")),
        }
    }
}

impl CmdExecutor for TextSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader = get_reader(&self.input)?;
        let key = get_content(&self.key)?;
        let sign = process_text_sign(&mut reader, &key, self.format)?;
        // 将sign再转化为base64
        let encoded = URL_SAFE_NO_PAD.encode(&sign);
        println!("{}", encoded);
        Ok(())
    }
}

impl CmdExecutor for TextVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader = get_reader(&self.input)?;
        let key = get_content(&self.key)?;
        let decoded = URL_SAFE_NO_PAD.decode(&self.sig)?;
        let verified = process_text_verify(&mut reader, &key, &decoded, self.format)?;
        if verified {
            println!("✅ Signature verified");
        } else {
            println!("❌ Signature not verified");
        }
        Ok(())
    }
}

impl CmdExecutor for KeyGenerateOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let key = process_text_key_generate(self.format)?;
        for (k, v) in key {
            fs::write(self.output_path.join(k), v)?;
        }
        Ok(())
    }
}

impl CmdExecutor for TextEncryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader = get_reader(&self.input)?;
        let key = get_content(&self.key)?;
        let ciphertext = process_text_encrypt(&mut reader, &key, self.format)?;
        let encoded = URL_SAFE_NO_PAD.encode(&ciphertext);
        println!("{}", encoded);
        Ok(())
    }
}

impl CmdExecutor for TextDecryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let decoded = get_content(&self.input)?;
        let key = get_content(&self.key)?;
        let ciphertext = URL_SAFE_NO_PAD.decode(&decoded)?;
        let plaintext = process_text_decrypt(&ciphertext, &key, self.format)?;
        println!("{}", String::from_utf8(plaintext)?);
        Ok(())
    }
}

impl CmdExecutor for TextSubCommand {
    async fn execute(self) -> anyhow::Result<()> {
        match self {
            TextSubCommand::Sign(opts) => opts.execute().await,
            TextSubCommand::Verify(opts) => opts.execute().await,
            TextSubCommand::Generate(opts) => opts.execute().await,
            TextSubCommand::Encrypt(opts) => opts.execute().await,
            TextSubCommand::Decrypt(opts) => opts.execute().await,
        }
    }
}
