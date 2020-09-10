extern crate yaml_rust;
use clap::{load_yaml, App};
extern crate openssl;

use std::io::prelude::*;
use std::io::BufReader;
//use std::io::BufWriter;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use openssl::symm::Cipher;
use openssl::pkcs7::{Pkcs7,Pkcs7Ref,Pkcs7Flags};
use openssl::stack::{Stack, StackRef};
use std::fs::{create_dir, File};
use std::path::Path;

#[cfg(test)]
mod tests {

    use std::fs::remove_file;
    // Pull all the imports from the rest of this file
    use super::*;

    #[test]
    fn test_key_creation() {
        let pub_name = "keys/pubtest.pkcs7.pem";
        let priv_name = "keys/privtest.pkcs7.pem";
        create_keys(&pub_name, &priv_name);

        // Verify cert is signed by key
        let pub_key_file = File::open(&pub_name).unwrap();
        let mut pub_reader = BufReader::new(pub_key_file);
        let priv_key_file = File::open(&priv_name).unwrap();
        let mut priv_reader = BufReader::new(priv_key_file);
        let mut pub_contents = Vec::new();
        let mut priv_contents = Vec::new();
        pub_reader.read_to_end(&mut pub_contents).unwrap();
        priv_reader.read_to_end(&mut priv_contents).unwrap();

        //let priv_key = Rsa::private_key_from_pem(&priv_contents).unwrap();
        //let pub_key = X509::from_pem(&pub_contents).unwrap();

        let priv_key = load_rsa_file_private(&priv_name);
        let pub_key = load_x509_file(&pub_name);
        assert_eq!(
            pub_key
                .verify(PKey::from_rsa(priv_key).unwrap().as_ref())
                .unwrap(),
            true
        );

        // Delete files
        remove_file(&pub_name).unwrap();
        remove_file(&priv_name).unwrap();
    }
}

fn load_rsa_file_private(private_key_filename: &str) -> Rsa<Private> {
    let priv_key_file = File::open(&private_key_filename).unwrap();
    let mut priv_reader = BufReader::new(priv_key_file);
    let mut priv_contents = Vec::new();
    priv_reader.read_to_end(&mut priv_contents).unwrap();
    let priv_key = Rsa::private_key_from_pem(&priv_contents).unwrap();
    return priv_key;
}

fn load_x509_file(public_key_filename: &str) -> X509 {
    let pub_key_file = File::open(&public_key_filename).unwrap();
    let mut pub_reader = BufReader::new(pub_key_file);
    let mut pub_contents = Vec::new();
    pub_reader.read_to_end(&mut pub_contents).unwrap();
    let pub_key = X509::from_pem(&pub_contents).unwrap();
    return pub_key;
}

fn encrypt_str(public_key_filename: &str, plaintext: &[u8]) {
    let encryption_algo: Cipher = Cipher::aes_256_cbc();
    
    let cert_content = load_x509_file(public_key_filename);

    let mut cert_stack = Stack::new().unwrap();
    cert_stack.push(cert_content).unwrap();
    
    Pkcs7::encrypt(
            cert_stack.as_ref(),
            plaintext,
            encryption_algo,
            Pkcs7Flags::empty(),
        ).unwrap();
    
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
    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("CN", "/").unwrap();
    let x509_name = x509_name.build();
    x509.set_subject_name(&x509_name).unwrap();
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
    // ensure our keys' parent dir exists
    // todo: make this dynamic/loop with both keys in case they're in different dirs
    if !Path::new(&public_key_filename).parent().unwrap().is_dir() {
        create_dir(Path::new(&public_key_filename).parent().unwrap()).unwrap();
    }
    let mut public_key_file = File::create(&public_key_filename).unwrap();
    public_key_file
        .write_all(&signed_x509.to_pem().unwrap())
        .unwrap();
    let mut private_key_file = File::create(&private_key_filename).unwrap();
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
            create_keys("keys/public_key.pkcs7.pem", "keys/private_key.pkcs7.pem");
        }
        Some("decrypt") => println!("This is not implemented yet."),
        Some("encrypt") => encrypt_str("keys/public_key.pkcs7.pem", "Hello World!".as_bytes()),
        Some("recrypt") => println!("This is not implemented yet."),
        Some("rekey") => println!("This is not implemented yet."),
        None => println!("No subcommand was specified."),
        _ => println!("Unknown subcommand specified"),
    }

    //println!("Args: {:#?}", args);
}
