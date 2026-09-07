//! Vanity address grinder: find a hearth signing key whose address starts with a
//! chosen string.
//!
//! ```text
//! cargo run --release --features vanity --bin hearth-vanity -- --prefix cafe
//! ```
//!
//! Each worker draws its own starting scalar from the OS CSPRNG and walks
//! `a_i = a_{i-1} + 1` / `A_i = A_{i-1} + B`; see [`hearth::vanity`] for why that
//! shape, and for the batched inversion that makes it fast. Every hit is
//! re-derived through the ordinary library path before it is printed, so a bug in
//! the fast path can cost hits but cannot print a key that does not match.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use hearth::address;
use hearth::ed25519::KeyPair;
use hearth::hex;
use hearth::vanity::{self, Hit, Pattern};

const USAGE: &str = "\
hearth-vanity — find a signing key whose address starts with a chosen string

USAGE:
    hearth-vanity --prefix <chars> [options]

OPTIONS:
    -p, --prefix <chars>   characters the address must have right after \"<hrp>1\"
                           (bech32 alphabet: qpzry9x8gf2tvdw0s3jn54khce6mua7l —
                           note it has no b, i, o or 1)
        --hrp <hrp>        address prefix to render and match against
                           [default: hrth; testnet is thrth]
    -t, --threads <n>      worker threads [default: all cores]
    -n, --count <n>        stop after finding this many keys [default: 1]
    -h, --help             show this help

The secret scalar is printed to stdout. Treat it as the private key it is: hand
it to KeyPair::from_scalar and it signs for the address shown.
";

struct Args {
    prefix: String,
    hrp: String,
    threads: usize,
    count: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut prefix = None;
    let mut hrp = address::MAINNET_HRP.to_string();
    let mut threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mut count = 1usize;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "-p" | "--prefix" => prefix = Some(value("--prefix")?),
            "--hrp" => hrp = value("--hrp")?,
            "-t" | "--threads" => {
                threads = value("--threads")?
                    .parse()
                    .map_err(|_| "--threads must be a positive integer".to_string())?
            }
            "-n" | "--count" => {
                count = value("--count")?
                    .parse()
                    .map_err(|_| "--count must be a positive integer".to_string())?
            }
            other => return Err(format!("unrecognized argument: {other}")),
        }
    }

    Ok(Args {
        prefix: prefix.ok_or("missing --prefix (see --help)")?,
        hrp,
        threads: threads.max(1),
        count: count.max(1),
    })
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("error: {message}");
            std::process::exit(2);
        }
    };

    let pattern = match Pattern::compile(&args.prefix) {
        Ok(pattern) => pattern,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };

    // Fail before spending hours if the HRP is malformed.
    if !address::valid_hrp(&args.hrp) {
        eprintln!(
            "error: '{}' is not a valid bech32 prefix (1..=83 lowercase a-z)",
            args.hrp
        );
        std::process::exit(2);
    }

    eprintln!(
        "searching for {}1{}… on {} thread(s); ~{:.3e} candidates expected per hit",
        args.hrp,
        pattern.text(),
        args.threads,
        pattern.expected_candidates()
    );

    let counter = AtomicU64::new(0);
    let stop = AtomicBool::new(false);
    let found = AtomicU64::new(0);
    let (tx, rx) = mpsc::channel::<(Hit, String)>();
    let started = Instant::now();

    std::thread::scope(|scope| {
        for _ in 0..args.threads {
            let tx = tx.clone();
            let (pattern, hrp, counter, stop, found) =
                (&pattern, &args.hrp, &counter, &stop, &found);
            let wanted = args.count as u64;
            scope.spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let start = vanity::random_start();
                    let Some(hit) = vanity::grind_from(pattern, &start, counter, stop) else {
                        return;
                    };
                    match hit.verify(pattern, hrp) {
                        Some(address) => {
                            if found.fetch_add(1, Ordering::Relaxed) + 1 >= wanted {
                                stop.store(true, Ordering::Relaxed);
                            }
                            let _ = tx.send((hit, address));
                        }
                        None => eprintln!(
                            "warning: fast path proposed a candidate that does not verify; \
                             discarding it (this is a bug — please report)"
                        ),
                    }
                }
            });
        }
        drop(tx);

        let mut reported = 0usize;
        loop {
            match rx.recv_timeout(Duration::from_secs(2)) {
                Ok((hit, addr)) => {
                    report(
                        &hit,
                        &addr,
                        started.elapsed(),
                        counter.load(Ordering::Relaxed),
                    );
                    reported += 1;
                    if reported >= args.count {
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    progress(counter.load(Ordering::Relaxed), started.elapsed(), &pattern)
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        stop.store(true, Ordering::Relaxed);
    });
}

fn progress(tried: u64, elapsed: Duration, pattern: &Pattern) {
    let rate = tried as f64 / elapsed.as_secs_f64().max(1e-9);
    let odds = 1.0 - (-(tried as f64) / pattern.expected_candidates()).exp();
    eprint!(
        "\r  {:>12} tried · {:>7.2} M/s · {:>5.1}% chance so far    ",
        tried,
        rate / 1e6,
        odds * 100.0
    );
    let _ = std::io::stderr().flush();
}

fn report(hit: &Hit, address: &str, elapsed: Duration, tried: u64) {
    let key = KeyPair::from_scalar(&hit.scalar).expect("verified above");
    eprintln!(
        "\r found after {} candidates in {:.1}s ({:.2} M/s overall)          ",
        hit.tries,
        elapsed.as_secs_f64(),
        tried as f64 / elapsed.as_secs_f64().max(1e-9) / 1e6
    );
    println!("address     : {address}");
    println!("public key  : {}", hex::encode(&key.public_key));
    println!(
        "scalar      : {}   <- SECRET: KeyPair::from_scalar(this)",
        hex::encode(&hit.scalar)
    );
    println!();
}
