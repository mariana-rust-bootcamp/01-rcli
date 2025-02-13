use clap::Parser;
use enum_dispatch::enum_dispatch;

use crate::{process_jwt_sign, process_jwt_verify, CmdExecutor};

/**
* CLI:
    rcli jwt sign --sub acme --aud device1 --exp 14d
    rcli jwt verify -t <token-value>
*/
#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum JwtSubCommand {
    #[command(about = "generate a jsonwebtoken")]
    Sign(JwtSignOpts),
    #[command(about = "verify a jsonwebtoken")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    #[arg(short, long)]
    pub sub: String,
    #[arg(short, long)]
    pub aud: String,
    #[arg(short, long, default_value = "14d")]
    pub exp: String,
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(short, long)]
    pub token: String,
}

impl CmdExecutor for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let token = process_jwt_sign(self.sub, self.aud, self.exp)?;
        println!("token: {}", token);
        Ok(())
    }
}

impl CmdExecutor for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let result = process_jwt_verify(&self.token);
        match result {
            Ok(claims) => println!("✅ Token verified! Valid claim: {}", claims),
            Err(err) => println!("❌ Token not verified! Invalid token: {}", err),
        }
        Ok(())
    }
}
