mod brute;
mod resolver;

use clap::{App, Arg, ArgMatches, Values};
use colored::*;
use futures::prelude::*;
use futures::stream;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use stream_throttle::{ThrottlePool, ThrottleRate};
use trust_dns_client::rr::rdata::caa::Value;
use trust_dns_client::rr::rdata::DNSSECRecordType;
use trust_dns_client::rr::RecordType;
use trust_dns_proto::rr::dnssec::rdata::DNSSECRData;
use trust_dns_proto::rr::rdata;
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
            Arg::with_name("OPERATION")
                .help("Operation to perform.")
                .required(true)
                .takes_value(true)
                .index(1)
                .possible_values(&["brute", "axfr", "dnssec"])
                .default_value("axfr")
                .requires_if("brute", "SUBDOMAINS"),
        )
        .arg(
            Arg::with_name("DOMAIN")
                .help("The domain to enumerate")
                .required(true)
                .takes_value(true)
                .index(2),
        )
        .arg(
            Arg::with_name("SUBDOMAINS")
                .short("s")
                .long("subdomains")
                .help("The subdomains file to enumerate")
                .required(false)
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
                .takes_value(true)
                .validator(validate_rate),
        )
        .arg(
            Arg::with_name("CONCURRENCY")
                .short("c")
                .long("concurrency")
                .help("The number of concurrent requests")
                .required(false)
                .default_value("1000")
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

    println!(
        "[{}] Use with caution.  You are responsible for your actions.",
        "WRN".yellow()
    );
    println!(
        "[{}] Developers assume no liability and are not responsible for any misuse or damage.",
        "WRN".yellow()
    );

    let operation = command.value_of("OPERATION").expect("operation expected");
    let domain = command.value_of("DOMAIN").expect("domain expected");
    let concurrency = command
        .value_of("CONCURRENCY")
        .expect("concurrency expected")
        .parse::<usize>()
        .unwrap();

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

    let records = if operation == "axfr" {
        if let Some(nameservers) = command.values_of("NAMES_SERVERS") {
            let name_server_port = command
                .value_of("NAME_SERVER_PORT")
                .expect("Port expected")
                .parse::<u16>()
                .expect("Port expected to be a number");
            let ns_ips = validate_name_servers(nameservers).await;
            resolver::query(
                domain,
                &ns_ips,
                name_server_port,
                concurrency,
                RecordType::AXFR,
            )
            .await
        } else {
            vec![]
        }
    } else if operation == "dnssec" {
        if let Some(nameservers) = command.values_of("NAMES_SERVERS") {
            let name_server_port = command
                .value_of("NAME_SERVER_PORT")
                .expect("Port expected")
                .parse::<u16>()
                .expect("Port expected to be a number");
            let ns_ips = validate_name_servers(nameservers).await;
            resolver::query_udp(
                domain,
                &ns_ips,
                name_server_port,
                concurrency,
                RecordType::DNSSEC(DNSSECRecordType::DNSKEY),
            )
            .await
        } else {
            vec![]
        }
    } else if operation == "brute" {
        let subdomains_file = command.value_of("SUBDOMAINS").expect("subdomains expected");
        brute::brute_force_domain(domain, subdomains_file, pool, &res, concurrency).await
    } else {
        println!("Unkown operation: {}", operation);
        vec![]
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
        RData::ANAME(name) => name.to_utf8(),
        RData::CAA(caa) => format!("{} {}", caa.tag().as_str(), display_rr_value(caa.value())),
        RData::MX(mx) => format!("{} {}", mx.preference(), mx.exchange().to_ascii()),
        RData::NAPTR(naptr) => format!(
            "{} {} {} {} {} {}",
            naptr.order(),
            naptr.preference(),
            std::str::from_utf8(naptr.flags())
                .map(|x| x.to_string())
                .unwrap_or_else(|_| base64::encode(naptr.flags())),
            std::str::from_utf8(naptr.services())
                .map(|x| x.to_string())
                .unwrap_or_else(|_| base64::encode(naptr.services())),
            std::str::from_utf8(naptr.regexp())
                .map(|x| x.to_string())
                .unwrap_or_else(|_| base64::encode(naptr.regexp())),
            naptr.replacement().to_ascii()
        ),
        RData::NULL(null) => displary_rr_null(null),
        RData::NS(name) => name.to_ascii(),
        RData::PTR(name) => name.to_ascii(),
        RData::OPENPGPKEY(key) => base64::encode(key.public_key()),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            soa.mname().to_ascii(),
            soa.rname().to_ascii(),
            soa.serial(),
            soa.refresh(),
            soa.retry(),
            soa.expire(),
            soa.minimum()
        ),
        RData::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority(),
            srv.weight(),
            srv.port(),
            srv.target().to_ascii(),
        ),
        RData::TXT(txt) => txt
            .txt_data()
            .iter()
            .map(|x| {
                std::str::from_utf8(&*(x))
                    .map(|x| x.to_string())
                    .unwrap_or_else(|_| base64::encode(&*x))
            })
            .collect::<Vec<_>>()
            .join(","),
        RData::Unknown { code, rdata } => format!("{} {}", code, displary_rr_null(rdata)),
        RData::DNSSEC(data) => displary_rr_dnssecrdata(data),
        _ => format!("{:?}", rdata),
    }
}

fn displary_rr_dnssecrdata(dnssec: &DNSSECRData) -> String {
    match dnssec {
        DNSSECRData::DNSKEY(key) => format!(
            "{} {} {} {} {}",
            key.zone_key(),
            key.secure_entry_point(),
            key.revoke(),
            key.algorithm(),
            base64::encode(key.public_key())
        ),
        DNSSECRData::DS(ds) => format!(
            "{} {} {:?} {}",
            ds.key_tag(),
            ds.algorithm(),
            ds.digest_type(),
            base64::encode(ds.digest())
        ),
        DNSSECRData::KEY(key) => format!(
            "{:?} {:?} {:?} {} {:?} {} {}",
            key.key_trust(),
            key.key_usage(),
            key.signatory(),
            key.revoke(),
            key.protocol(),
            key.algorithm(),
            base64::encode(key.public_key())
        ),
        DNSSECRData::NSEC(ns) => {
            let type_bms = ns
                .type_bit_maps()
                .iter()
                .map(|x| format!("{}", x))
                .collect::<Vec<_>>()
                .join(",");
            format!("{} {}", ns.next_domain_name().to_ascii(), type_bms)
        }
        _ => format!("{:?}", dnssec),
    }
}

fn displary_rr_null(null: &rdata::NULL) -> String {
    null.anything()
        .map(|x| {
            std::str::from_utf8(x)
                .map(|x| x.to_string())
                .unwrap_or_else(|_| base64::encode(x))
        })
        .unwrap_or_else(|| "".to_string())
}

fn display_rr_value(value: &Value) -> String {
    match value {
        Value::Issuer(None, params) if params.is_empty() => "".to_string(),
        Value::Issuer(None, params) => params
            .iter()
            .map(|v| format!("{}:{}", v.key(), v.value()))
            .collect::<Vec<_>>()
            .join(" "),
        Value::Issuer(Some(name), params) if params.is_empty() => format!("{}", name),
        Value::Issuer(Some(name), params) => {
            let value_fmt = params
                .iter()
                .map(|v| format!("{}:{}", v.key(), v.value()))
                .collect::<Vec<_>>()
                .join(" ");
            format!("{} {}", name, value_fmt)
        }
        Value::Url(url) => url.to_string(),
        Value::Unknown(unknown) => base64::encode(unknown),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use trust_dns_client::rr::Name;
    use trust_dns_proto::rr::rdata;

    #[test]
    fn test_display_rdata_a_rec() {
        let ip = "127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap();
        assert_eq!(display_rdata(&RData::A(ip)), format!("{}", ip))
    }

    #[test]
    fn test_display_rdata_aaaa_rec() {
        let ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
            .parse::<std::net::Ipv6Addr>()
            .unwrap();
        assert_eq!(display_rdata(&RData::AAAA(ip)), format!("{}", ip))
    }

    #[test]
    fn test_display_rdata_aname_rec() {
        let name = Name::from_str("localhost").unwrap();
        let name_format = format!("{}", &name.to_utf8());
        assert_eq!(display_rdata(&RData::ANAME(name)), name_format);
    }

    #[test]
    fn test_display_rdata_caa_rec_issue() {
        let name = Name::from_str("localhost").unwrap();
        let caa = rdata::caa::CAA::new_issue(false, Some(name), vec![]);
        assert_eq!(display_rdata(&RData::CAA(caa)), "issue localhost");
    }

    #[test]
    fn test_display_rdata_mx_rec() {
        let name = Name::from_str("localhost").unwrap();
        let mx = rdata::MX::new(0, name);
        assert_eq!(display_rdata(&RData::MX(mx)), "0 localhost");
    }

    #[test]
    fn test_display_rdata_naptr_rec() {
        let name = Name::from_str("localhost").unwrap();
        let flags = String::from("flags").into_bytes().into_boxed_slice();
        let services = String::from("services").into_bytes().into_boxed_slice();
        let regexp = String::from("regexp").into_bytes().into_boxed_slice();
        let naptr = rdata::NAPTR::new(0, 1, flags, services, regexp, name);
        assert_eq!(
            display_rdata(&RData::NAPTR(naptr)),
            "0 1 flags services regexp localhost"
        );
    }

    #[test]
    fn test_display_rdata_null_rec() {
        let data = "test".to_string().into_bytes();
        let null_rec = rdata::NULL::with(data.clone());
        assert_eq!(display_rdata(&RData::NULL(null_rec)), "test")
    }

    #[test]
    fn test_display_rdata_ns_rec() {
        let name = Name::from_str("localhost").expect("Name should be valid");
        assert_eq!(display_rdata(&RData::NS(name)), "localhost");
    }

    #[test]
    fn test_display_rdata_ptr_rec() {
        let name = Name::from_str("localhost").expect("Name should be valid");
        assert_eq!(display_rdata(&RData::PTR(name)), "localhost");
    }

    #[test]
    fn test_display_rdata_opengpkey_rec() {
        let key = vec![10_u8; 10];
        let opengpkey = rdata::OPENPGPKEY::new(key.clone());
        assert_eq!(
            display_rdata(&RData::OPENPGPKEY(opengpkey)),
            base64::encode(key)
        );
    }

    #[test]
    fn test_display_rdata_soa_rec() {
        let mname = Name::from_str("mname").expect("Name should be valid");
        let rname = Name::from_str("rname").expect("Name should be valid");
        let soa = rdata::SOA::new(mname, rname, 0, 1, 2, 3, 4);
        assert_eq!(display_rdata(&RData::SOA(soa)), "mname rname 0 1 2 3 4");
    }

    #[test]
    fn test_display_rdata_srv_rec() {
        let name = Name::from_str("name").expect("Name should be valid");
        let srv = rdata::SRV::new(0, 1, 2, name);
        assert_eq!(display_rdata(&RData::SRV(srv)), "0 1 2 name");
    }

    #[test]
    fn test_display_rdata_txt_rec() {
        let txt_values = vec!["test".to_string(), "testing".to_string()];
        let txt = rdata::TXT::new(txt_values);
        assert_eq!(display_rdata(&RData::TXT(txt)), "test,testing");
    }

    #[test]
    fn test_display_rdata_unknown_rec() {
        let data = "test".to_string().into_bytes();
        let null_rec = rdata::NULL::with(data.clone());
        let unknown = RData::Unknown {
            code: 10,
            rdata: null_rec,
        };
        assert_eq!(display_rdata(&unknown), "10 test");
    }
}
