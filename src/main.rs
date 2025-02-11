use anyhow::Result;
use clap::Parser;
use rcli::{CmdExecutor, Opts, SubCommand};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let opts = Opts::parse();
    match opts.cmd {
        SubCommand::Csv(opts) => opts.execute().await,
        SubCommand::GenPass(opts) => opts.execute().await,
        SubCommand::Base64(cmd) => cmd.execute().await,
        SubCommand::Text(cmd) => cmd.execute().await,
        SubCommand::Http(cmd) => cmd.execute().await,
    }
}
