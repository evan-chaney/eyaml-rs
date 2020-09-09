extern crate yaml_rust;
use clap::{load_yaml, App, SubCommand};
extern crate openssl;

use bytes::Bytes;
use std::io::prelude::*;
//use std::io::BufWriter;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use std::fs::{create_dir, File};
use std::path::Path;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_creation(){
        let pub_name = "pubtest.pkcs7.pem";
        let priv_name = "privtest.pkcs7.pem";
        create_keys(&pub_name, &priv_name);

    }

}


fn create_keys(public_key_filename: &str, private_key_filename: &str) {
    // Basically doing the same as this openssl command
    // openssl req -x509 -nodes -days 100000 -newkey rsa:2048 -keyout privatekey.pem -out publickey.pem -subj '/'

    // Create RSA private key
    let private_key = Rsa::generate(2048).unwrap();

    // Generate cert and sign

    let mut x509 = X509Builder::new().unwrap();

    // Create ref for our timeperiod
    let not_after = Asn1Time::days_from_now(100000).unwrap();
    x509.set_not_after(&not_after).unwrap();
    x509.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    // Build our name
    //let mut x509_name = X509NameBuilder::new().unwrap();
    //x509_name.append_entry_by_text("Subject", "/").unwrap();
    // let x509_name = x509_name.build();

    //x509.set_subject_name(&x509_name).unwrap();
    x509.set_version(2).unwrap();
    x509.set_pubkey(&PKey::from_rsa(private_key.clone()).unwrap())
        .unwrap();
    x509.sign(
        PKey::from_rsa(private_key.clone()).unwrap().as_ref(),
        MessageDigest::sha256(),
    )
    .unwrap();
    // todo add error messaging if the signing fails
    let signed_x509: X509 = x509.build();

    // Write files
    // ensure our keys dir exists
    if !Path::new("keys").is_dir() {
        create_dir("keys").unwrap();
    }
    let mut public_key_file = File::create(format!("keys/{}", &public_key_filename)).unwrap();
    public_key_file
        .write_all(&signed_x509.to_pem().unwrap())
        .unwrap();
    let mut private_key_file = File::create(format!("keys/{}", &private_key_filename)).unwrap();
    private_key_file
        .write_all(&private_key.private_key_to_pem().unwrap())
        .unwrap();
    println!("Keys generated and written to files!")
}

fn main() {
    let cli_yaml = load_yaml!("cli.yaml");
    let args = App::from(cli_yaml).get_matches();

    // Flow for different subcommands
    match args.subcommand_name() {
        Some("createkeys") => {
            println!("createkeys was specified.");
            create_keys("public_key.pkcs7.pem", "private_key.pkcs7.pem");
        }
        Some("decrypt") => println!("This is not implemented yet."),
        Some("encrypt") => println!("This is not implemented yet."),
        Some("recrypt") => println!("This is not implemented yet."),
        Some("rekey") => println!("This is not implemented yet."),
        None => println!("No subcommand was specified."),
        _ => println!("Unknown subcommand specified"),
    }

    //println!("Args: {:#?}", args);
}
