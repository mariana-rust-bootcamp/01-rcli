use crate::{process_genpass, CmdExecutor};
use clap::Parser;
use zxcvbn::zxcvbn;

/// 生成密码
#[derive(Debug, Parser)]
pub struct GenPassOpts {
    #[arg(short, long, default_value_t = 16)]
    pub length: u8,
    #[arg(long, default_value_t = true)]
    pub uppercase: bool,
    #[arg(long, default_value_t = true)]
    pub lowercase: bool,
    #[arg(long, default_value_t = true)]
    pub number: bool,
    #[arg(long, default_value_t = true)]
    pub symbols: bool,
}

impl CmdExecutor for GenPassOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let ret = process_genpass(
            self.length,
            self.uppercase,
            self.lowercase,
            self.number,
            self.symbols,
        )?;
        // 将打印从通用方法中移出
        println!("{}", ret);

        let estimate = zxcvbn(&ret, &[]);
        // eprintln!在pipe时不显示, score()显示密码强度0-4(低-高)
        eprintln!("Password strength: {}", estimate.score());
        Ok(())
    }
}
