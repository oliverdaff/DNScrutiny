use clap::{App, Arg};
use std::path::Path;
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

    let domain = command.value_of("DOMAIN").unwrap();

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let res = resolver.await.expect("Failed to connect to resolver");
    let response = res
        .lookup_ip(domain)
        .await
        .expect("Failed to resolve address");
    response.iter().for_each(|x| {
        println!("{:?}", x);
    })
}

fn validate_subdomain_file(file: String) -> Result<(), String> {
    if Path::new(&file).is_file() {
        Ok(())
    } else {
        Err(format!("File not fount: {}", file))
    }
}
