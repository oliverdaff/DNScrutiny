# DNScrutiny [![CircleCI](https://circleci.com/gh/oliverdaff/hprobe.svg?style=shield)](https://circleci.com/gh/oliverdaff/DNScrutiny) [![GitHub release (latest by date)](https://img.shields.io/github/v/release/oliverdaff/DNScrutiny?style=plastic)](https://github.com/oliverdaff/DNScrutiny/releases/latest)

Carries out DNS information gathering:
    * Performs a domain transfer against the name servers
    * Performs subdomain enumeration for the domain from the subdomain file.

## Installation

### Cargo

## Usage
Install latest from GitHub using Cargo.

```bash
git checkout https://github.com/oliverdaff/DNScrutiny
cargo test 
cargo install --path .
```


### Basic

Run a DNS name transfer request
```
dnscrutiny axfr zonetransfer.me -n nsztm1.digi.ninja
```


Run a DNS subdomain enumeration for the domain.
```
dnscrutiny brute thedomain.com -s /Users/oliver/opt/SecLists/Discovery/DNS/namelist.txt -n 8.8.8.8,1.1.1.1
```
### Flags And Options

## Docker

## Tests

## Credits
This project was inspired by [DNSRecon](https://github.com/darkoperator/dnsrecon).

## License
MIT © Oliver Daff