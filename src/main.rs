mod brute;
mod transfer;

use clap::{App, Arg, ArgMatches, Values};
use futures::prelude::*;
use futures::stream;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use stream_throttle::{ThrottlePool, ThrottleRate};
use trust_dns_proto::rr::record_data::RData;
use trust_dns_resolver::config::NameServerConfigGroup;
use trust_dns_resolver::config::*;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};

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
            Arg::with_name("TRANSFER")
                .long("axfr")
                .help("Perform a domain transfer request.")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::with_name("SUBDOMAINS")
                .short("s")
                .long("subdomains")
                .help("The subdomains file to enumerate")
                .required(false)
                .takes_value(true)
                .validator(validate_subdomain_file)
                .conflicts_with_all(&["TRANSFER"]),
        )
        .arg(
            Arg::with_name("RATE")
                .short("r")
                .long("rate")
                .help("The number of queries per second to issue")
                .required(false)
                .default_value("100")
                .takes_value(true)
                .validator(validate_rate),
        )
        .arg(
            Arg::with_name("NAMES_SERVERS")
                .short("n")
                .long("names-servers")
                .help("A comma-separated list of name servers to use")
                .takes_value(true)
                .required(false)
                .multiple(true)
                .value_delimiter(","),
        )
        .arg(
            Arg::with_name("NAME_SERVER_PORT")
                .short("p")
                .long("name-server-port")
                .help("The port to use for the name server")
                .required(false)
                .default_value("53")
                .validator(validate_name_server_port)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("GOGGLE_NS")
                .long("google-ns")
                .help("Use the google name servers")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::with_name("QUAD9_NS")
                .long("quad9-ns")
                .help("Use the quad9 name servers")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::with_name("CLOUDFLARE_NS")
                .long("cloudflare-ns")
                .help("Use the cloudflare name servers")
                .required(false)
                .takes_value(false),
        )
        .get_matches();

    let domain = command.value_of("DOMAIN").expect("domain expected");

    let query_per_sec = command
        .value_of("RATE")
        .expect("rate expected")
        .parse::<usize>()
        .unwrap();

    let rate = ThrottleRate::new(query_per_sec, Duration::from_secs(1));
    let pool = ThrottlePool::new(rate);

    let resolver_config =
        ResolverConfig::from_parts(None, vec![], fetch_resolve_config(&command).await);

    let resolver = TokioAsyncResolver::tokio(
        resolver_config,
        ResolverOpts {
            preserve_intermediates: true,
            ..ResolverOpts::default()
        },
    );

    let res = resolver.await.expect("Failed to connect to resolver");

    let records = if command.is_present("TRANSFER") {
        if let Some(nameservers) = command.values_of("NAMES_SERVERS") {
            let name_server_port = command
                .value_of("NAME_SERVER_PORT")
                .expect("Port expected")
                .parse::<u16>()
                .expect("Port expected to be a number");
            let ns_ips = validate_name_servers(nameservers).await;
            transfer::transfer_request(domain, &ns_ips, name_server_port).await
        } else {
            vec![]
        }
    } else {
        let subdomains_file = command.value_of("SUBDOMAINS").expect("subdomains expected");
        brute::brute_force_domain(domain, subdomains_file, pool, &res).await
    };

    println!("*********************");
    println!("Results");
    println!("*********************");
    for record in records {
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

async fn fetch_resolve_config(command: &ArgMatches<'_>) -> NameServerConfigGroup {
    let mut config = NameServerConfigGroup::new();
    if command.is_present("GOGGLE_NS") {
        NameServerConfigGroup::merge(&mut config, NameServerConfigGroup::google())
    }
    if command.is_present("CLOUDFLARE_NS") {
        NameServerConfigGroup::merge(&mut config, NameServerConfigGroup::cloudflare())
    }
    if command.is_present("QUAD9_NS") {
        NameServerConfigGroup::merge(&mut config, NameServerConfigGroup::quad9())
    }
    if let Some(nameservers) = command.values_of("NAMES_SERVERS") {
        let name_server_port = command
            .value_of("NAME_SERVER_PORT")
            .expect("Port expected")
            .parse::<u16>()
            .expect("Port expected to be a number");
        let ns_config = NameServerConfigGroup::from_ips_clear(
            &validate_name_servers(nameservers).await,
            name_server_port,
        );
        NameServerConfigGroup::merge(&mut config, ns_config)
    }
    if !command.is_present("GOGGLE_NS")
        && !command.is_present("CLOUDFLARE_NS")
        && !command.is_present("QUAD9_NS")
        && !command.is_present("NAMES_SERVERS")
    {
        NameServerConfigGroup::merge(&mut config, NameServerConfigGroup::google())
    }
    config
}

async fn validate_name_servers(ns_args: Values<'_>) -> Vec<IpAddr> {
    let resolver = AsyncResolver::tokio_from_system_conf()
        .await
        .expect("Error creating system config resolver");
    let x = stream::iter(ns_args)
        .then(|maybe_ip| validate_name_server(maybe_ip, &resolver))
        .collect::<Vec<Result<_, _>>>()
        .await;
    let (ips, errors): (Vec<_>, Vec<_>) = x.into_iter().partition(|x| x.is_ok());
    errors
        .into_iter()
        .map(Result::unwrap_err)
        .for_each(|e| println!("Error resolving name sever {}", e));
    let ips = ips
        .into_iter()
        .map(Result::unwrap)
        .flatten()
        .collect::<Vec<_>>();
    if ips.is_empty() {
        panic!("No valid name servers found.")
    }
    println!("Name servers have been validated {:?}", ips);
    ips
}

async fn validate_name_server(
    ns_arg: &str,
    res: &TokioAsyncResolver,
) -> Result<Vec<IpAddr>, ResolveError> {
    if let Ok(ip) = ns_arg.parse::<IpAddr>() {
        Ok(vec![ip])
    } else {
        res.lookup_ip(ns_arg)
            .await
            .map(|ip_lookup| ip_lookup.iter().collect::<Vec<IpAddr>>())
    }
}
