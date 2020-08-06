# DNScrutiny [![CircleCI](https://circleci.com/gh/oliverdaff/hprobe.svg?style=shield)](https://circleci.com/gh/oliverdaff/DNScrutiny) [![GitHub release (latest by date)](https://img.shields.io/github/v/release/oliverdaff/DNScrutiny?style=plastic)](https://github.com/oliverdaff/DNScrutiny/releases/latest)

Carries out DNS recon gathering:

*   Performs a domain transfer against the name servers
*   Performs subdomain enumeration for the domain from the subdomain file.

## Installation
The latest release binaries can be downloaded from Github (Coming soon).

### Cargo

Install latest from GitHub using Cargo.

```bash
git checkout https://github.com/oliverdaff/DNScrutiny
cargo test 
cargo install --path .
```

## Usage

Run a DNS name transfer request
```
dnscrutiny axfr zonetransfer.me -n nsztm1.digi.ninja
```

Run a DNS subdomain enumeration for the domain.
```
dnscrutiny brute thedomain.com -s /usr/share/opt/SecLists/Discovery/DNS/namelist.txt -n 8.8.8.8,1.1.1.1
```

### Flags And Options

```
USAGE:
    dnscrutiny [FLAGS] [OPTIONS] <OPERATION> <DOMAIN> --subdomains <SUBDOMAINS>

FLAGS:
        --cloudflare-ns    Use the cloudflare name servers
        --google-ns        Use the google name servers
        --quad9-ns         Use the quad9 name servers
    -h, --help             Prints help information
    -V, --version          Prints version information

OPTIONS:
    -c, --concurrency <CONCURRENCY>              The number of concurrent requests [default: 1000]
    -n, --names-servers <NAMES_SERVERS>...       A comma-separated list of name servers to use
    -p, --name-server-port <NAME_SERVER_PORT>    The port to use for the name server [default: 53]
    -r, --rate <RATE>                            The number of queries per second to issue [default: 100]
    -s, --subdomains <SUBDOMAINS>                The subdomains file to enumerate

ARGS:
    <OPERATION>    Operation to perform. [default: axfr]  [possible values: brute, axfr]
    <DOMAIN>       The domain to enumerate
```

Name server flags a accumulative so using `--cloudflare-ns --google-ns --quad9-ns` will use all three name servers for resolution.

## Docker
Build the docker container by first using `cargo cross` to build the static binaries.

```shell
cargo install cross
cross build --target x86_64-unknown-linux-musl --release
```

Then build the docker container

```
docker build -t dnscrutiny .
```

Run the container using:
*    `-i` flag to map stdin to into the container.
*    `--rm` to remove the container on exit
*   `2>/dev/null` sterr redirection to hide failed connection detail.

```
docker run -i --rm dnscrutiny <args>
```

## Tests
The tests can be invoked with `cargo test`

## Credits
This project was inspired by [DNSRecon](https://github.com/darkoperator/dnsrecon).

## License
MIT © Oliver Daff