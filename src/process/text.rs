use anyhow::{Ok, Result};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::{collections::HashMap, io::Read};

use crate::{cli::TextSignFormat, get_reader};

use super::process_genpass;

pub trait TextSigner {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool>;
}

pub trait TextEncrypter {
    fn encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextDecrypter {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

pub struct Chacha20 {
    key: Key,
    nonce: Nonce,
}

impl TextSigner for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        // key由genpass命令生成长度为 32的密钥
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes().to_vec())
    }
}

impl TextVerifier for Blake3 {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        // Vec实现了PartialEq, 可以直接比较
        Ok(ret.as_bytes() == sig)
    }
}

impl TextSigner for Ed25519Signer {
    // 使用私钥生成签名
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        // vscode自动引入的可能有问题, 需要注意官方文档
        // self.key为私钥 buf为明文
        let signature = self.key.sign(&buf);
        Ok(signature.to_bytes().to_vec())
    }
}

impl TextVerifier for Ed25519Verifier {
    // 使用公钥验证签名
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        // sig为未定长切片, 需要转化为指定长度的数组
        let sig = sig[..64].try_into()?;
        let signature = Signature::from_bytes(sig);
        // self.key 为公钥 buf为明文
        Ok(self.key.verify(&buf, &signature).is_ok())
    }
}

impl TextEncrypter for Chacha20 {
    fn encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        // 明文->密文
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let cipher = ChaCha20Poly1305::new(&self.key);
        let ciphertext = cipher
            .encrypt(&self.nonce, buf.as_ref())
            .map_err(|err| anyhow::anyhow!(err))?; // 将ChaCha20Poly1305的错误转换为anyhow的错误
        Ok(ciphertext)
    }
}

impl TextDecrypter for Chacha20 {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // 密文->明文
        let cipher = ChaCha20Poly1305::new(&self.key);
        let plaintext = cipher
            .decrypt(&self.nonce, ciphertext.as_ref())
            .map_err(|err| anyhow::anyhow!(err))?;
        Ok(plaintext)
    }
}

// 实现方法关键字不能使用pub
impl Blake3 {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = key[..32].try_into()?;
        Ok(Self::new(key))
    }
    // 构造函数参数没有self, Self表示类名
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
    pub fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let mut map = HashMap::new();
        map.insert("blake3.txt", key.as_bytes().to_vec());
        Ok(map)
    }
}

impl Ed25519Signer {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = key[..32].try_into()?;
        Ok(Self::new(key))
    }
    // 利用SigningKey::from_bytes将bytes数组转换为SigningKey
    pub fn new(key: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(key);
        Self { key }
    }
    // 利用SigningKey::generate生成公钥和私钥
    pub fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key();
        let mut map = HashMap::new();
        map.insert("ed25519.sk", sk.as_bytes().to_vec());
        map.insert("ed25519.pk", pk.as_bytes().to_vec());

        Ok(map)
    }
}

impl Ed25519Verifier {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = key[..32].try_into()?;
        let key = VerifyingKey::from_bytes(key)?;
        Ok(Self { key })
    }
}

impl Chacha20 {
    pub fn try_new(input: &[u8]) -> Result<Self> {
        let key = Key::clone_from_slice(input);
        let mut nonce = Vec::new();
        let mut reader = get_reader("fixtures/chacha20.nonce")?;
        reader.read_to_end(&mut nonce)?;
        let nonce = Nonce::clone_from_slice(&nonce);
        Ok(Self::new(key, nonce))
    }

    pub fn new(key: Key, nonce: Nonce) -> Self {
        Self { key, nonce }
    }

    pub fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let mut map = HashMap::new();
        map.insert("chacha20.key", key.to_vec());
        map.insert("chacha20.nonce", nonce.to_vec());

        Ok(map)
    }
}

/**
 * reader 明文
 * key 对称加密密钥{ or 非对称加密私钥 }
 * format 加密算法
 */
pub fn process_text_sign(
    reader: &mut dyn Read,
    key: &[u8],
    format: TextSignFormat,
) -> Result<Vec<u8>> {
    let signer: Box<dyn TextSigner> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Signer::try_new(key)?),
        _ => return Err(anyhow::anyhow!("unsupported format")),
    };

    signer.sign(reader)
}

pub fn process_text_verify(
    reader: &mut dyn Read,
    key: &[u8],
    sig: &[u8],
    format: TextSignFormat,
) -> Result<bool> {
    let verifier: Box<dyn TextVerifier> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Verifier::try_new(key)?),
        _ => return Err(anyhow::anyhow!("unsupported format")),
    };
    verifier.verify(reader, sig)
}

pub fn process_text_key_generate(format: TextSignFormat) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
        TextSignFormat::Chacha20Poly1305 => Chacha20::generate(),
        // _ => Err(anyhow::anyhow!("unsupported format")),
    }
}

pub fn process_text_encrypt(
    reader: &mut dyn Read,
    key: &[u8],
    format: TextSignFormat,
) -> Result<Vec<u8>> {
    let encryptor: Box<dyn TextEncrypter> = match format {
        TextSignFormat::Chacha20Poly1305 => Box::new(Chacha20::try_new(key)?),
        _ => return Err(anyhow::anyhow!("unsupported format")),
    };

    encryptor.encrypt(reader)
}

pub fn process_text_decrypt(
    ciphertext: &[u8],
    key: &[u8],
    format: TextSignFormat,
) -> Result<Vec<u8>> {
    let decryptor: Box<dyn TextDecrypter> = match format {
        TextSignFormat::Chacha20Poly1305 => Box::new(Chacha20::try_new(key)?),
        _ => return Err(anyhow::anyhow!("unsupported format")),
    };

    decryptor.decrypt(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::TextSignFormat;
    use anyhow::{Ok, Result};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    const KEY: &[u8] = include_bytes!("../../fixtures/blake3.txt");
    const ENCRYPTKEY: &[u8] = include_bytes!("../../fixtures/chacha20.key");

    #[test]
    fn test_process_text_sign() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let mut reader1 = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = process_text_sign(&mut reader, KEY, format)?;
        let ret = process_text_verify(&mut reader1, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_verify() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = "oIaTKaAdK6rz-DuYaiOIYMmRtmDAq3Dpx6QcpmESeH0";
        let sig = URL_SAFE_NO_PAD.decode(sig)?;
        let ret = process_text_verify(&mut reader, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_encrypt() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let format = TextSignFormat::Chacha20Poly1305;
        let ciphertext = process_text_encrypt(&mut reader, ENCRYPTKEY, format)?;
        let plaintext = process_text_decrypt(&ciphertext, ENCRYPTKEY, format)?;
        assert!(String::from_utf8(plaintext)? == "hello");
        Ok(())
    }
}
