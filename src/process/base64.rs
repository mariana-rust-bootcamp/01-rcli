use std::io::Read;

use crate::cli::Base64Format;
use anyhow::Result;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};

pub fn process_encode(reader: &mut dyn Read, format: Base64Format) -> Result<String> {
    let mut buf = Vec::new();
    // 将文件或标准输入读入内存
    reader.read_to_end(&mut buf)?;
    let encoded = match format {
        Base64Format::Standard => STANDARD.encode(&buf),
        Base64Format::UrlSafe => URL_SAFE_NO_PAD.encode(&buf),
    };
    println!("{}", encoded);
    Ok(encoded)
}

pub fn process_decode(reader: &mut dyn Read, format: Base64Format) -> Result<String> {
    let mut buf = String::new();
    // 以utf8的编码方式读取文件或标准输入
    reader.read_to_string(&mut buf)?;
    // 需要去除首尾的空白字符, 否则会decode失败
    let buf = buf.trim();
    let decoded = match format {
        Base64Format::Standard => STANDARD.decode(buf)?,
        Base64Format::UrlSafe => URL_SAFE_NO_PAD.decode(buf)?,
    };
    // 处理字符串并打印
    let decoded = String::from_utf8(decoded)?;
    // 如果是处理非文本文件需要直接写入
    // File::create(".jpg")?.write_all(&decoded)?; // 生成文件
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::get_reader;
    use anyhow::Ok;
    use anyhow::Result;

    #[test]
    fn test_process_encode() -> Result<()> {
        let input = "Cargo.toml";
        let mut reader = get_reader(input)?;
        let format = Base64Format::Standard;
        assert!(process_encode(&mut reader, format).is_ok());
        Ok(())
    }

    #[test]
    fn test_process_decode() -> Result<()> {
        let input = "fixtures/b64.txt";
        let mut reader = get_reader(input)?;
        let format = Base64Format::UrlSafe;
        assert!(process_decode(&mut reader, format).is_ok());
        Ok(())
    }
}
