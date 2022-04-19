#![allow(non_snake_case)]

use blocks_iterator::{Config, PeriodCounter};
use env_logger::Env;
use log::{info, warn, debug};
use std::error::Error;
use std::sync::mpsc::sync_channel;
use std::time::Duration;
use blocks_iterator::structopt::StructOpt;
use miniscript::{Miniscript, Terminal, ScriptContext};
use bitcoin::Script;

fn check_script<Ctx: ScriptContext>(s: &Script) -> bool {
    if let Ok(ms) = Miniscript::<_, Ctx>::parse(s) {
        debug!("Valid Miniscript script: {:?}", ms);

        ms.iter().filter_map(|ms| match &ms.node {
            Terminal::Thresh(_, inner) => Some(inner),
            _ => None,
        }).any(|inner| inner.iter().any(|inner_ms| match &inner_ms.node {
            Terminal::After(_) | Terminal::Older(_) => true,
            _ => false,
        }))
    } else {
        false
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("start");

    let config = Config::from_args();
    let (send, recv) = sync_channel(config.channels_size.into());
    let handle = blocks_iterator::iterate(config, send);
    let mut period = PeriodCounter::new(Duration::from_secs(10));

    while let Some(block_extra) = recv.recv()? {
        if period.period_elapsed().is_some() {
            info!(
                "# {:7} {}",
                block_extra.height,
                block_extra.block_hash,
            );
        }

        // if block_extra.height < 610682 {
        if block_extra.height < 100 {
            continue;
        }

        for tx in block_extra.block.txdata {
            for input in tx.input {
                fn check<Ctx: ScriptContext>(s: &Script, prev_out: &bitcoin::OutPoint) {
                    if check_script::<Ctx>(s) {
                        warn!("Found vulnerable input: {}", prev_out);
                    }
                }

                let script_pubkey = &block_extra.outpoint_values.get(&input.previous_output).expect("Missing txout").script_pubkey;
                if script_pubkey.is_p2sh() {
                    if input.script_sig.is_v0_p2wsh() {
                        check::<miniscript::Segwitv0>(&Script::from(input.witness.iter().last().unwrap().clone()), &input.previous_output);
                    } else if input.script_sig.is_v0_p2wpkh() {
                        // ignore instead of trying to parse needlessly
                    } else if let Some(Ok(bitcoin::blockdata::script::Instruction::PushBytes(bytes))) = input.script_sig.instructions().last() {
                        check::<miniscript::Legacy>(&Script::from(bytes.to_vec()), &input.previous_output);
                    }
                } else if script_pubkey.is_v0_p2wsh() {
                    check::<miniscript::Segwitv0>(&Script::from(input.witness.iter().last().unwrap().clone()), &input.previous_output);
                }
            }
        }
    }
    handle.join().expect("couldn't join");

    Ok(())
}

