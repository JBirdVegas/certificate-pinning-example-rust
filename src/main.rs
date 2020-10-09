extern crate crypto;
extern crate curl;
extern crate openssl;
extern crate serde_json;

use std::net::TcpStream;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use curl::http;
use nom::AsBytes;
use rustls::Session;
use rustls_connector::{rustls, RustlsConnector};
use serde_json::Value;
use url::Url;

#[derive(Clone)]
struct CertLoader<'a> {
    domain: &'a str,
}

/// calls the domain's 443 port and makes a sha256 hash of each certificate
/// found in the chain.
fn load_certificate_hashes_via_local(domain: CertLoader) -> Vec<String> {
    // parse url. try really hard
    let url_parsed = Url::parse(&format!("https://{}", domain.domain));
    let url = Url::parse(&*domain.domain)
        .or_else(|err| url_parsed.map_err(|_| err))
        .unwrap();

    let mut config = rustls::ClientConfig::new();
    config.root_store = rustls_native_certs::load_native_certs()
        .expect("could not load platform certs");
    let connector: RustlsConnector = config.into();

    // connect
    let result = url.socket_addrs(|| Some(443)).unwrap();
    let stream = TcpStream::connect(result[0]).unwrap();
    let host_str = url.host_str().unwrap();
    let stream = connector.connect(host_str, stream).unwrap();

    // get certs
    let chain = stream
        .sess
        .get_peer_certificates()
        .unwrap();

    let mut vec = Vec::new();
    let mut sha256 = Sha256::new();
    // make a hash for each cert in the chain
    for c in chain {
        sha256.input(c.as_ref().as_bytes());
        vec.push(sha256.result_str());
        sha256.reset()
    }
    return vec;
}

/// Gets certificate hashes for each certificate found in the chain.
/// As seen from the public internet
fn load_certificate_hashes_via_api(domain: CertLoader) -> Vec<String> {
    let domain_to_validate = domain.domain;
    let resp = http::handle()
        .get(&*format!("https://api.cert.ist/{}", domain_to_validate))
        .exec()
        .unwrap_or_else(|e| {
            panic!("Failed to get domain; error is {}", e);
        });

    if resp.get_code() != 200 {
        println!("Unable to handle HTTP response code {:?}",
                 std::char::from_u32(resp.get_code()));
        return Vec::new();
    }

    let body = std::str::from_utf8(resp.get_body()).unwrap_or_else(|e| {
        panic!("Failed to parse response; error is {}", e);
    });

    let json: Value = serde_json::from_str(body).unwrap_or_else(|e| {
        panic!("Failed to parse json; error is {}", e);
    });

    let cert_chain = json.as_object()
        .and_then(|object| object.get("chain"))
        .and_then(|cert| cert.as_array());

    let mut vec = Vec::new();
    for number in 0..cert_chain.unwrap().len() {
        let s = cert_chain
            .and_then(|hashes| hashes.get(number))
            .and_then(|sha| sha.get("der"))
            .and_then(|sha| sha.get("hashes"))
            .and_then(|sha| sha.get("sha256"))
            .and_then(|s256| s256.as_str())
            .unwrap_or_else(|| {
                panic!("Failed to get '.certificate.hashes.sha256' value from json");
            });
        vec.push(s.to_string());
    }
    return vec;
}

fn vec_compare(first: Vec<String>, second: Vec<String>) -> bool {
    if first.len() != second.len() {
        return false;
    }
    for n in 0..first.len() {
        if !second.contains(first.get(n).unwrap()) {
            return false;
        }
    }
    return true;
}

fn pin_certificates_for_domain(certificate_loader: CertLoader) {
    let hash_from_local = load_certificate_hashes_via_local(certificate_loader.clone());
    let hash_from_api = load_certificate_hashes_via_api(certificate_loader.clone());

    // verify the entire chain equals and exactly the same
    let are_equal = vec_compare(hash_from_local, hash_from_api);
    println!("Did the domain {}'s certificates, as seen locally, match what the API reports? {}",
             certificate_loader.domain, are_equal);
}

fn main() {
    pin_certificates_for_domain(CertLoader { domain: "asciirange.com" });
    pin_certificates_for_domain(CertLoader { domain: "tilltrump.com" });
    pin_certificates_for_domain(CertLoader { domain: "cert.ist" });
    pin_certificates_for_domain(CertLoader { domain: "urip.io" });
    std::process::exit(0);
}
