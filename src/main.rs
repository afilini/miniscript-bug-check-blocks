#![allow(non_snake_case)]

use bitcoin::consensus::Decodable;
use bitcoin::{self, Script, TxIn, TxOut};
use blocks_iterator::bitcoin::consensus::Encodable;
use blocks_iterator::structopt::StructOpt;
use blocks_iterator::{BlockExtra, Config};
use env_logger::Env;
use log::{debug, info, warn};
use miniscript_old::{Legacy, Miniscript, ScriptContext, Segwitv0, Terminal};
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// Check if the miniscript has a d-wrapper. This does not do a recursive check
fn is_d_wrapped<Ctx: ScriptContext>(ms: &Miniscript<bitcoin::PublicKey, Ctx>) -> bool {
    match &ms.node {
        Terminal::True
        | Terminal::False
        | Terminal::PkK(_)
        | Terminal::PkH(_)
        | Terminal::After(_)
        | Terminal::Older(_)
        | Terminal::Sha256(_)
        | Terminal::Hash256(_)
        | Terminal::Ripemd160(_)
        | Terminal::Hash160(_)
        | Terminal::AndV(_, _)
        | Terminal::AndB(_, _)
        | Terminal::AndOr(_, _, _)
        | Terminal::OrB(_, _)
        | Terminal::OrD(_, _)
        | Terminal::OrC(_, _)
        | Terminal::OrI(_, _)
        | Terminal::Thresh(_, _)
        | Terminal::Multi(_, _) => false,
        Terminal::Alt(ms)
        | Terminal::Swap(ms)
        | Terminal::Check(ms)
        | Terminal::Verify(ms)
        | Terminal::NonZero(ms)
        | Terminal::ZeroNotEqual(ms) => is_d_wrapped(&ms),
        Terminal::DupIf(_ms) => true,
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CheckRes {
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
            if ms
                .iter()
                .filter_map(|ms| match &ms.node {
                    Terminal::Thresh(_, inner) => Some(inner),
                    _ => None,
                })
                .any(|inner| inner.iter().any(|inner_ms| is_d_wrapped(&inner_ms)))
            {
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

fn pre_processing(mut block_extra: BlockExtra) -> Vec<(TxIn, TxOut)> {
    let mut vec = vec![];
    for tx in block_extra.block.txdata {
        for input in tx.input {
            let txout = block_extra
                .outpoint_values
                .remove(&input.previous_output)
                .unwrap();

            // blocks_iterator use bitcoin 0.28, while miniscript to be tested 0.27 and to work
            // a ser/de roundtrip is made
            vec.push((convert_txin(input), convert_txout(txout)));
        }
    }
    vec
}

fn convert_txin(txin: blocks_iterator::bitcoin::TxIn) -> bitcoin::TxIn {
    let mut serialized = Vec::with_capacity(128); // educated guess, may be more
    txin.consensus_encode(&mut serialized).unwrap();
    let mut txin_027 = bitcoin::TxIn::consensus_decode(&serialized[..]).unwrap();
    serialized.clear();
    txin.witness.consensus_encode(&mut serialized).unwrap(); // witness must be treated separetely
    txin_027.witness = Decodable::consensus_decode(&serialized[..]).unwrap();
    txin_027
}

fn convert_txout(txout: blocks_iterator::bitcoin::TxOut) -> bitcoin::TxOut {
    let mut serialized = Vec::with_capacity(64); // educated guess, may be more
    txout.consensus_encode(&mut serialized).unwrap();
    Decodable::consensus_decode(&serialized[..]).unwrap()
}

fn task(data: (TxIn, TxOut), error_count: Arc<AtomicUsize>) -> bool {
    fn check<Ctx: ScriptContext, Ctx2: miniscript_new::ScriptContext>(
        s: &Script,
        prev_out: &bitcoin::OutPoint,
        error_count: Arc<AtomicUsize>,
    ) {
        match check_script::<Ctx, Ctx2>(s) {
            CheckRes::MaybeVuln => {
                error_count.fetch_add(1, Ordering::SeqCst);
                warn!("Found potentially vulnerable input: {}", prev_out)
            }
            CheckRes::Vuln => {
                error_count.fetch_add(1, Ordering::SeqCst);
                warn!("Found vulnerable input: {}", prev_out);
            }
            CheckRes::Safe => {}
        }
    }

    let (input, prevout) = data;

    let script_pubkey = &prevout.script_pubkey;
    if script_pubkey.is_p2sh() {
        if input.script_sig.is_v0_p2wsh() {
            check::<Segwitv0, miniscript_new::Segwitv0>(
                &Script::from(input.witness.iter().last().unwrap().clone()),
                &input.previous_output,
                error_count.clone(),
            );
        } else if input.script_sig.is_v0_p2wpkh() {
            // ignore instead of trying to parse needlessly
        } else if let Some(Ok(bitcoin::blockdata::script::Instruction::PushBytes(bytes))) =
            input.script_sig.instructions().last()
        {
            check::<Legacy, miniscript_new::Legacy>(
                &Script::from(bytes.to_vec()),
                &input.previous_output,
                error_count.clone(),
            );
        }
    } else if script_pubkey.is_v0_p2wsh() {
        check::<Segwitv0, miniscript_new::Segwitv0>(
            &Script::from(input.witness.iter().last().unwrap().clone()),
            &input.previous_output,
            error_count.clone(),
        );
    }

    false
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("start");

    let config = Config::from_args();
    let state = Arc::new(AtomicUsize::new(0));

    blocks_iterator::par_iter(config, state.clone(), pre_processing, task);

    info!("Vulnerabilities found: {}", state.load(Ordering::SeqCst));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn _check_vuln_script(expected: CheckRes, s: &str) {
        let ms = Miniscript::<bitcoin::PublicKey, Segwitv0>::from_str(s).unwrap();
        assert_eq!(
            expected,
            check_script::<Segwitv0, miniscript_new::Segwitv0>(&ms.encode())
        );
    }

    #[test]
    fn check_vuln_scripts() {
        _check_vuln_script(
            CheckRes::Safe,
            "c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)",
        );

        _check_vuln_script(CheckRes::Vuln, "thresh(3,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),sc:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),sc:pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),sdv:older(32))");

        // If we add `n` wrapper also, it is no longer vulnerable. See: https://github.com/sipa/miniscript/pull/117/files
        _check_vuln_script(CheckRes::Safe, "thresh(3,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),sc:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),sc:pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),sndv:older(32))");
    }
}
