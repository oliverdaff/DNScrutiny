use clap::{App, Arg};
use futures::prelude::*;
use futures::stream;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::path::Path;
use std::time::Duration;
use stream_throttle::{ThrottlePool, ThrottleRate, ThrottledStream};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

#[tokio::main]
async fn main() {
    let command = App::new("Scrutiny")
        .version("0.1.0")
        .author("Oliver Daff")
        .about("A DNS subdomain brute force")
        .arg(
            Arg::with_name("DOMAIN")
                .help("The domain to enumerate")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("SUBDOMAINS")
                .short("s")
                .long("subdomains")
                .help("The subdomains to enumerate")
                .required(true)
                .takes_value(true)
                .validator(validate_subdomain_file),
        )
        .get_matches();

    let domain = command.value_of("DOMAIN").expect("domain expected");
    let subdomains_file = command.value_of("SUBDOMAINS").expect("subdomains expected");

    let file = File::open(subdomains_file).expect("Could not open file");
    let reader = BufReader::new(file);

    let rate = ThrottleRate::new(100, Duration::from_secs(1));
    let pool = ThrottlePool::new(rate);

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let res = resolver.await.expect("Failed to connect to resolver");

    let stream = stream::iter(reader.lines())
        .throttle(pool)
        .map_err(|e| format!("error {}", e))
        .and_then(|prefix| {
            res.lookup_ip(format!("{}.{}", prefix, domain))
                .map_err(|e| format!("error: {}", e))
        })
        .filter(|x| future::ready(x.is_ok()))
        .for_each(|x| {
            if let Ok(r) = x {
                println!("{:?}", r);
            }
            future::ready(())
        });
    stream.await;
}

fn validate_subdomain_file(file: String) -> Result<(), String> {
    if Path::new(&file).is_file() {
        Ok(())
    } else {
        Err(format!("File not fount: {}", file))
    }
}
