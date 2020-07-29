mod brute;

use clap::{App, Arg};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use stream_throttle::{ThrottlePool, ThrottleRate};
use trust_dns_proto::rr::record_data::RData;
use trust_dns_resolver::config::NameServerConfigGroup;
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
                .help("The subdomains file to enumerate")
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
        .arg(
            Arg::with_name("NAMES_SERVERS")
                .short("n")
                .long("names-servers")
                .help("A comma-separated list of name servers to use")
                .required(false)
                .multiple(true)
                .value_delimiter(",")
                .validator(validate_name_servers),
        )
        .arg(
            Arg::with_name("NAME_SERVER_PORT")
                .short("p")
                .long("name-server-port")
                .help("The port to use for the name server")
                .required(false)
                .default_value("53")
                .validator(validate_name_server_port),
        )
        .get_matches();

    let domain = command.value_of("DOMAIN").expect("domain expected");
    let subdomains_file = command.value_of("SUBDOMAINS").expect("subdomains expected");
    let name_server_port = command
        .value_of("NAME_SERVER_PORT")
        .expect("Port expected")
        .parse::<u16>()
        .expect("Port expected to be a number");

    let query_per_sec = command
        .value_of("RATE")
        .expect("rate expected")
        .parse::<usize>()
        .unwrap();

    let rate = ThrottleRate::new(query_per_sec, Duration::from_secs(1));
    let pool = ThrottlePool::new(rate);

    let resolver_config =
        command
            .values_of("NAMES_SERVERS")
            .map_or(ResolverConfig::default(), |ips| {
                ResolverConfig::from_parts(
                    None,
                    vec![],
                    NameServerConfigGroup::from_ips_clear(
                        &ips.map(|x| x.parse().unwrap()).collect::<Vec<IpAddr>>(),
                        name_server_port,
                    ),
                )
            });

    let resolver = TokioAsyncResolver::tokio(
        resolver_config,
        ResolverOpts {
            preserve_intermediates: true,
            ..ResolverOpts::default()
        },
    );

    let res = resolver.await.expect("Failed to connect to resolver");

    let records = brute::brute_force_domain(domain, subdomains_file, pool, &res);

    println!("*********************");
    println!("Results");
    println!("*********************");
    for record in records.await {
        println!(
            "{}:{}:{}",
            record.name().to_ascii(),
            record.record_type(),
            display_rdata(record.rdata())
        );
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

fn validate_name_servers(name_server: String) -> Result<(), String> {
    name_server
        .parse::<IpAddr>()
        .map(|_| ())
        .map_err(|_| format!("Invalid IP address {}", name_server))
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
        Err(_) => Err(format!("Rate must be a number {}", rate)),
        Ok(_) => Ok(()),
    }
}

fn validate_name_server_port(port: String) -> Result<(), String> {
    port.parse::<u16>()
        .map(|_| ())
        .map_err(|_| format!("Invalid name server port: {}", port))
}
