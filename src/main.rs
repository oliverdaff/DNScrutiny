use clap::{App, Arg};
use futures::prelude::*;
use futures::stream;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::path::Path;
use std::time::Duration;
use stream_throttle::{ThrottlePool, ThrottleRate, ThrottledStream};
use trust_dns_proto::rr::record_data::RData;
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
        .arg(
            Arg::with_name("RATE")
                .short("r")
                .long("rate")
                .help("The number of queries per second to issue")
                .required(false)
                .default_value("100")
                .validator(validate_rate),
        )
        .get_matches();

    let domain = command.value_of("DOMAIN").expect("domain expected");
    let subdomains_file = command.value_of("SUBDOMAINS").expect("subdomains expected");
    let query_per_sec = command
        .value_of("RATE")
        .expect("rate expected")
        .parse::<usize>()
        .unwrap();

    let file = File::open(subdomains_file).expect("Could not open file");
    let reader = BufReader::new(file);

    let rate = ThrottleRate::new(query_per_sec, Duration::from_secs(1));
    let pool = ThrottlePool::new(rate);

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts {
            preserve_intermediates: true,
            ..ResolverOpts::default()
        },
    );

    let res = resolver.await.expect("Failed to connect to resolver");

    let stream = stream::iter(reader.lines())
        .throttle(pool)
        .map_err(|e| format!("error {}", e))
        .and_then(|prefix| {
            res.lookup_ip(format!("{}.{}", prefix, domain))
                .map_err(|e| format!("error: {}", e))
        })
        .filter(|x| future::ready(x.is_ok()))
        .map(|x| x.unwrap())
        .inspect(|x| {
            println!("{:?}", x);
        });
    let results = stream.collect::<Vec<_>>().await;

    println!("*********************");
    println!("Results");
    println!("*********************");
    for result in results {
        for record in result.as_lookup().record_iter() {
            println!(
                "{}:{}:{}",
                record.name().to_ascii(),
                record.record_type(),
                display_rdata(record.rdata())
            );
        }
    }
}

fn display_rdata(rdata: &RData) -> String {
    match rdata {
        RData::A(ip) => format!("{}", ip),
        RData::AAAA(ip) => format!("{}", ip),
        RData::CNAME(name) => name.to_utf8(),
        _ => format!("{:?}", rdata),
    }
}

fn validate_subdomain_file(file: String) -> Result<(), String> {
    if Path::new(&file).is_file() {
        Ok(())
    } else {
        Err(format!("File not fount: {}", file))
    }
}

fn validate_rate(rate: String) -> Result<(), String> {
    match rate.parse::<usize>() {
        Err(_) => Err(format!("Rate must be a number")),
        Ok(_) => Ok(()),
    }
}
