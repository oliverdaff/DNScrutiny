use futures::prelude::*;
use futures::stream;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::fs::File;
use std::io::{prelude::*, BufReader};
use stream_throttle::{ThrottlePool, ThrottledStream};
use trust_dns_proto::rr::Record;
use trust_dns_resolver::TokioAsyncResolver;

pub async fn brute_force_domain(
    domain: &str,
    subdomains_file: &str,
    throttle_pool: ThrottlePool,
    resolver: &TokioAsyncResolver,
) -> Vec<Record> {
    if let Ok(result) = is_wildcard_domain(domain, resolver).await {
        println!("Wild card resolution is enabled on this domain");
        println!("All domains will resolve to these ips");
        return result
            .as_lookup()
            .record_iter()
            .cloned()
            .collect::<Vec<_>>();
    }

    let file = File::open(subdomains_file).expect("Could not open file");
    let reader = BufReader::new(file);

    let stream = stream::iter(reader.lines())
        .throttle(throttle_pool)
        .map_err(|e| format!("error {}", e))
        .and_then(|prefix| {
            resolver
                .lookup_ip(format!("{}.{}", prefix, domain))
                .map_err(|e| format!("error: {}", e))
        })
        .filter(|x| future::ready(x.is_ok()))
        .map(|x| x.unwrap())
        .map(|x| x.as_lookup().clone());
    stream
        .collect::<Vec<_>>()
        .await
        .iter()
        .flat_map(|x| x.record_iter().cloned())
        .collect::<Vec<_>>()
}

/// Check if domain is configured with Wildcard resolution
/// by requesting a random address
async fn is_wildcard_domain(
    domain: &str,
    resolver: &TokioAsyncResolver,
) -> Result<trust_dns_resolver::lookup_ip::LookupIp, trust_dns_resolver::error::ResolveError> {
    let prefix: String = thread_rng().sample_iter(&Alphanumeric).take(12).collect();
    resolver.lookup_ip(format!("{}.{}", prefix, domain)).await
}
