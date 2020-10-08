extern crate crypto;
extern crate curl;
extern crate openssl;
extern crate serde_json;

use std::net::TcpStream;
use std::sync::Arc;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use curl::http;
use nom::AsBytes;
use rustls::Session;
use rustls_connector::{rustls, RustlsConnector, webpki};
use serde_json::Value;
use url::Url;

pub struct NoCertificateVerification;

impl rustls::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef<'_>,
        _ocsp: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

#[derive(Clone)]
struct CertLoader<'a> {
    domain: &'a str,
}


fn load_remote_certificate(domain: CertLoader) -> String {
    // parse url. try really hard
    let url_parsed = Url::parse(&format!("https://{}", domain.domain));
    let url = Url::parse(&*domain.domain)
        .or_else(|err| url_parsed.map_err(|_| err))
        .unwrap();

    // disable verification since we want to perform the validation manually
    let mut config = rustls::ClientConfig::new();
    config.dangerous().set_certificate_verifier(Arc::new(NoCertificateVerification));
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

    let bytes = chain.first().unwrap().as_ref().as_bytes();
    let mut sha256 = Sha256::new();
    sha256.input(bytes);
    // println!("{:?}", sha256.result_str());
    return sha256.result_str();
}

fn get_from_api(domain: CertLoader) -> String {
    let domain_to_validate = domain.domain;
    let resp = http::handle()
        .get(&*format!("https://api.cert.ist/{}", domain_to_validate))
        .exec()
        .unwrap_or_else(|e| {
            panic!("Failed to get domain; error is {}", e);
        });

    if resp.get_code() != 200 {
        println!("Unable to handle HTTP response code {}", resp.get_code());
        return "".to_string();
    }

    let body = std::str::from_utf8(resp.get_body()).unwrap_or_else(|e| {
        panic!("Failed to parse response; error is {}", e);
    });

    let json: Value = serde_json::from_str(body).unwrap_or_else(|e| {
        panic!("Failed to parse json; error is {}", e);
    });

    let sha256_value = json.as_object()
        .and_then(|object| object.get("certificate"))
        .and_then(|cert| cert.as_object())
        .and_then(|hashes| hashes.get("hashes"))
        .and_then(|sha| sha.get("sha256"))
        .and_then(|s256| s256.as_str())
        .unwrap_or_else(|| {
            panic!("Failed to get '.certificate.hashes.sha256' value from json");
        });
    return sha256_value.to_string();
}

fn pin_cert_to_domain(certificate_loader: CertLoader) {
    let string = load_remote_certificate(certificate_loader.clone());
    let hash_from_api = get_from_api(certificate_loader.clone());
    let do_the_match = if string == hash_from_api { "yes" } else { "nope" };
    println!("Did the domain {}'s certificate, as seen locally, match what the API reports? {}",
             certificate_loader.domain, do_the_match);
}

fn main() {
    pin_cert_to_domain(CertLoader { domain: "asciirange.com" });
    pin_cert_to_domain(CertLoader { domain: "tilltrump.com" });
    pin_cert_to_domain(CertLoader { domain: "cert.ist" });
    pin_cert_to_domain(CertLoader { domain: "urip.io" });
    std::process::exit(0);
}
