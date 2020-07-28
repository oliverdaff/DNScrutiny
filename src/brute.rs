use futures::prelude::*;
use futures::stream;
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
