use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;
use trust_dns_client::client::AsyncClient;
use trust_dns_client::rr::dnssec::Signer;
use trust_dns_client::rr::{DNSClass, Name, Record, RecordType};
use trust_dns_client::tcp::TcpClientStream;
use trust_dns_proto::xfer::DnsMultiplexer;
use trust_dns_proto::{iocompat::AsyncIo02As03, TokioTime};

use trust_dns_client::client::*;

// Perform a Domain Transfer Request
pub async fn transfer_request(domain: &str, name_servers: &Vec<IpAddr>, port: u16) -> Vec<Record> {
    let mut results = vec![];
    for address in name_servers {
        let socket = SocketAddr::new(*address, port);
        let (stream, sender) =
            TcpClientStream::<AsyncIo02As03<TcpStream>>::new::<TokioTime>(socket);
        let mp = DnsMultiplexer::new(stream, sender, None::<Arc<Signer>>);
        let client = AsyncClient::connect(mp);
        let (mut client, bg) = client.await.expect("Failed to create client");
        tokio::spawn(bg);

        let name = Name::from_str(domain).unwrap();
        let query = client.query(name, DNSClass::IN, RecordType::AXFR);
        let response = query.await.expect("Request Failed");
        let answers = response.answers();
        results.extend(answers.iter().cloned());
    }
    results
}
