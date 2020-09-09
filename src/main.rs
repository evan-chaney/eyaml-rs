extern crate yaml_rust;
use clap::{load_yaml, App};
extern crate openssl;

use openssl::rsa::{Rsa, Padding};
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;

fn create_keys() {
    // Basically doing the same as this openssl command
    // openssl req -x509 -nodes -days 100000 -newkey rsa:2048 -keyout privatekey.pem -out publickey.pem -subj '/'

    // Create RSA private key
    let private_key = Rsa::generate(2048).unwrap();

    // Generate cert and sign
  
    let mut public_key = X509Builder::new().unwrap();
    
    // Create ref for our timeperiod
    let not_after = Asn1Time::days_from_now(100000).unwrap();
    public_key.set_not_after(&not_after).unwrap();
    public_key.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref()).unwrap();
    public_key.sign(
        PKey::from_rsa(private_key.clone()).unwrap().as_ref()     
        , MessageDigest::sha256()).unwrap();
    // todo add error messaging if the signing fails    


    // Write files
}

fn main() {
    let cli_matches = App::from(load_yaml!("cli.yaml")).get_matches();
}
