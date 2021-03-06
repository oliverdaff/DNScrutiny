use futures::prelude::*;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use trust_dns_client::client::AsyncClient;
use trust_dns_client::rr::dnssec::Signer;
use trust_dns_client::rr::{DNSClass, Name, Record, RecordType};
use trust_dns_client::tcp::TcpClientStream;
use trust_dns_client::udp::UdpClientStream;
use trust_dns_proto::xfer::DnsMultiplexer;
use trust_dns_proto::{iocompat::AsyncIo02As03, TokioTime};

use trust_dns_client::client::*;

pub async fn query(
    domain: &str,
    name_servers: &[IpAddr],
    port: u16,
    concurrency: usize,
    record_type: RecordType,
) -> Vec<Record> {
    let (records, errors): (Vec<_>, Vec<_>) = stream::iter(name_servers)
        .then(|address| {
            let socket = SocketAddr::new(*address, port);
            let (stream, sender) =
                TcpClientStream::<AsyncIo02As03<TcpStream>>::new::<TokioTime>(socket);
            let mp = DnsMultiplexer::new(stream, sender, None::<Arc<Signer>>);
            AsyncClient::connect(mp).map_err(move |_| {
                format!("Failed to create client for address: {}:{}", address, port)
            })
        })
        .and_then(|(client, bg)| {
            tokio::spawn(bg);
            async {
                Name::from_str(domain)
                    .map(|name| (client, name, domain))
                    .map_err(|_| format!("Failed to create name: {}", domain))
            }
        })
        .map_ok(|(mut client, name, domain)| {
            client
                .query(name, DNSClass::IN, record_type)
                .map_err(move |_| format!("{} query failed: {}", record_type, domain))
        })
        .try_buffer_unordered(concurrency)
        .map_ok(|response| response.answers().to_vec())
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .partition(Result::is_ok);
    let records = records
        .into_iter()
        .map(|x| x.unwrap())
        .flatten()
        .collect::<Vec<_>>();
    errors
        .into_iter()
        .map(|x| x.unwrap_err())
        .for_each(|e| println!("{:?}", e));
    records
}

pub async fn query_udp(
    domain: &str,
    name_servers: &[IpAddr],
    port: u16,
    concurrency: usize,
    record_type: RecordType,
) -> Vec<Record> {
    let (records, errors): (Vec<_>, Vec<_>) = stream::iter(name_servers)
        .then(|address| {
            let socket = SocketAddr::new(*address, port);
            let stream = UdpClientStream::<UdpSocket>::new(socket);
            AsyncClient::connect(stream).map_err(move |_| {
                format!("Failed to create client for address: {}:{}", address, port)
            })
        })
        .and_then(|(client, bg)| {
            tokio::spawn(bg);
            async {
                Name::from_str(domain)
                    .map(|name| (client, name, domain))
                    .map_err(|_| format!("Failed to create name: {}", domain))
            }
        })
        .map_ok(|(mut client, name, domain)| {
            client
                .query(name, DNSClass::IN, record_type)
                .map_err(move |_| format!("{} query failed: {}", record_type, domain))
        })
        .try_buffer_unordered(concurrency)
        .map_ok(|response| response.answers().to_vec())
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .partition(Result::is_ok);
    let records = records
        .into_iter()
        .map(|x| x.unwrap())
        .flatten()
        .collect::<Vec<_>>();
    errors
        .into_iter()
        .map(|x| x.unwrap_err())
        .for_each(|e| println!("{:?}", e));
    records
}
