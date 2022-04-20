#![allow(non_snake_case)]

use blocks_iterator::{Config, PeriodCounter};
use env_logger::Env;
use log::{info, warn, debug};
use std::error::Error;
use std::sync::mpsc::sync_channel;
use std::time::Duration;
use blocks_iterator::structopt::StructOpt;
use miniscript_old::{Miniscript, Terminal, ScriptContext, Segwitv0, Legacy};
use bitcoin::Script;

// Check if the miniscript has a d-wrapper. This does not do a recursive check
fn is_d_wrapped<Ctx: ScriptContext>(ms: &Miniscript<bitcoin::PublicKey, Ctx>) -> bool {

    match &ms.node {
        Terminal::True |
        Terminal::False |
        Terminal::PkK(_) |
        Terminal::PkH(_) |
        Terminal::After(_) |
        Terminal::Older(_) |
        Terminal::Sha256(_) |
        Terminal::Hash256(_) |
        Terminal::Ripemd160(_) |
        Terminal::Hash160(_) |
        Terminal::AndV(_, _) |
        Terminal::AndB(_, _) |
        Terminal::AndOr(_, _, _) |
        Terminal::OrB(_, _) |
        Terminal::OrD(_, _) |
        Terminal::OrC(_, _) |
        Terminal::OrI(_, _) |
        Terminal::Thresh(_, _) |
        Terminal::Multi(_, _)  => false,
        Terminal::Alt(ms) |
        Terminal::Swap(ms) |
        Terminal::Check(ms) |
        Terminal::Verify(ms) |
        Terminal::NonZero(ms) |
        Terminal::ZeroNotEqual(ms) => is_d_wrapped(&ms),
        Terminal::DupIf(_ms) => true,
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CheckRes{
    MaybeVuln,
    Vuln,
    Safe,
}

fn check_script<Ctx: ScriptContext, Ctx2: miniscript_new::ScriptContext>(s: &Script) -> CheckRes {
    if let Ok(ms) = Miniscript::<_, Ctx>::parse(s) {
        debug!("Valid Miniscript script: {:?}", ms);

        // Check if the new miniscript fails to parse this
        // This does not necessarily mean a bug, because there are some harmless combinations with `or_c` and `or_d`
        if let Err(_e) = miniscript_new::Miniscript::<_, Ctx2>::parse(s) {
            if ms.iter().filter_map(|ms| match &ms.node {
                Terminal::Thresh(_, inner) => Some(inner),
                _ => None,
            }).any(|inner| inner.iter().any(|inner_ms| is_d_wrapped(&inner_ms))) {
                CheckRes::Vuln
            } else {
                CheckRes::MaybeVuln
            }
        } else {
            CheckRes::Safe
        }
    } else {
        CheckRes::Safe
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

        // First block of 2020
        if block_extra.height < 610682 {
        // if block_extra.height < 100 {
            continue;
        }

        for tx in block_extra.block.txdata {
            for input in tx.input {
                fn check<Ctx: ScriptContext, Ctx2: miniscript_new::ScriptContext>(s: &Script, prev_out: &bitcoin::OutPoint) {
                    match check_script::<Ctx, Ctx2>(s) {
                        CheckRes::MaybeVuln => warn!("Found potentially vulnerable input: {}", prev_out),
                        CheckRes::Vuln => warn!("Found vulnerable input: {}", prev_out),
                        CheckRes::Safe => {},
                    }
                }

                let script_pubkey = &block_extra.outpoint_values.get(&input.previous_output).expect("Missing txout").script_pubkey;
                if script_pubkey.is_p2sh() {
                    if input.script_sig.is_v0_p2wsh() {
                        check::<Segwitv0, miniscript_new::Segwitv0>(&Script::from(input.witness.iter().last().unwrap().clone()), &input.previous_output);
                    } else if input.script_sig.is_v0_p2wpkh() {
                        // ignore instead of trying to parse needlessly
                    } else if let Some(Ok(bitcoin::blockdata::script::Instruction::PushBytes(bytes))) = input.script_sig.instructions().last() {
                        check::<Legacy, miniscript_new::Legacy>(&Script::from(bytes.to_vec()), &input.previous_output);
                    }
                } else if script_pubkey.is_v0_p2wsh() {
                    check::<Segwitv0, miniscript_new::Segwitv0>(&Script::from(input.witness.iter().last().unwrap().clone()), &input.previous_output);
                }
            }
        }
    }
    handle.join().expect("couldn't join");

    Ok(())
}


#[cfg(test)]
mod tests{
    use super::*;
    use std::str::FromStr;

    fn _check_vuln_script(expected: CheckRes, s: &str) {
        let ms = Miniscript::<bitcoin::PublicKey, Segwitv0>::from_str(s).unwrap();
        assert_eq!(expected, check_script::<Segwitv0, miniscript_new::Segwitv0>(&ms.encode()));
    }

    #[test]
    fn check_vuln_scripts() {
        _check_vuln_script(CheckRes::Safe, "c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)");

        _check_vuln_script(CheckRes::Vuln, "thresh(3,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),sc:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),sc:pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),sdv:older(32))");

        // If we add `n` wrapper also, it is no longer vulnerable. See: https://github.com/sipa/miniscript/pull/117/files
        _check_vuln_script(CheckRes::Safe, "thresh(3,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),sc:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),sc:pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),sndv:older(32))");
    }

}
