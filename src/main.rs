use std::fs;

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use rcli::{
    get_content, get_reader, process_csv, process_decode, process_encode, process_genpass,
    process_http_serve, process_text_decrypt, process_text_encrypt, process_text_key_generate,
    process_text_sign, process_text_verify, Base64SubCommand, HttpSubCommand, Opts, SubCommand,
    TextSubCommand,
};
use zxcvbn::zxcvbn;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let opts = Opts::parse();
    match opts.cmd {
        SubCommand::Csv(opts) => {
            let output = if let Some(output) = opts.output {
                output.clone()
            } else {
                format!("output.{}", opts.format)
            };
            process_csv(&opts.input, output, opts.format)?;
        }
        SubCommand::GenPass(opts) => {
            let ret = process_genpass(
                opts.length,
                opts.uppercase,
                opts.lowercase,
                opts.number,
                opts.symbols,
            )?;
            // 将打印从通用方法中移出
            println!("{}", ret);

            let estimate = zxcvbn(&ret, &[]);
            // eprintln!在pipe时不显示, score()显示密码强度0-4(低-高)
            eprintln!("Password strength: {}", estimate.score());
        }
        SubCommand::Base64(cmd) => match cmd {
            Base64SubCommand::Encode(opts) => {
                let mut reader = get_reader(&opts.input)?;
                let ret = process_encode(&mut reader, opts.format)?;
                println!("{}", ret);
            }
            Base64SubCommand::Decode(opts) => {
                let mut reader = get_reader(&opts.input)?;
                let ret = process_decode(&mut reader, opts.format)?;
                println!("{}", ret);
            }
        },
        SubCommand::Text(cmd) => match cmd {
            TextSubCommand::Sign(opts) => {
                let mut reader = get_reader(&opts.input)?;
                let key = get_content(&opts.key)?;
                let sign = process_text_sign(&mut reader, &key, opts.format)?;
                // 将sign再转化为base64
                let encoded = URL_SAFE_NO_PAD.encode(&sign);
                println!("{}", encoded);
            }
            TextSubCommand::Verify(opts) => {
                let mut reader = get_reader(&opts.input)?;
                let key = get_content(&opts.key)?;
                let decoded = URL_SAFE_NO_PAD.decode(&opts.sig)?;
                let verified = process_text_verify(&mut reader, &key, &decoded, opts.format)?;
                if verified {
                    println!("✅ Signature verified");
                } else {
                    println!("❌ Signature not verified");
                }
            }
            TextSubCommand::Generate(opts) => {
                let key = process_text_key_generate(opts.format)?;
                for (k, v) in key {
                    fs::write(opts.output_path.join(k), v)?;
                }
            }
            TextSubCommand::Encrypt(opts) => {
                let mut reader = get_reader(&opts.input)?;
                let key = get_content(&opts.key)?;
                let ciphertext = process_text_encrypt(&mut reader, &key, opts.format)?;
                let encoded = URL_SAFE_NO_PAD.encode(&ciphertext);
                println!("{}", encoded);
            }
            TextSubCommand::Decrypt(opts) => {
                let decoded = get_content(&opts.input)?;
                let key = get_content(&opts.key)?;
                let ciphertext = URL_SAFE_NO_PAD.decode(&decoded)?;
                let plaintext = process_text_decrypt(&ciphertext, &key, opts.format)?;
                println!("{}", String::from_utf8(plaintext)?);
            }
        },
        SubCommand::Http(cmd) => match cmd {
            HttpSubCommand::Serve(opts) => {
                process_http_serve(opts.dir, opts.port).await?;
            }
        },
    }
    Ok(())
}
