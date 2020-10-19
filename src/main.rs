extern crate yaml_rust;
use clap::{load_yaml, App};
extern crate openssl;

use std::io::prelude::*;
use std::io::BufReader;
//use std::io::BufWriter;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use std::ffi::OsStr;
use std::fs::{create_dir, read_to_string, File};
use std::path::Path;
use std::str::from_utf8;
use std::{
    env::{temp_dir, var},
    io::Read,
    process::{exit, Command},
};
use tempfile::{tempfile, NamedTempFile};

#[cfg(test)]
mod tests {

    use std::fs::remove_file;
    // Pull all the imports from the rest of this file
    use super::*;

    fn setup_test() {
        let test_dir = "test.tmp";
        if !Path::new(&test_dir).is_dir() {
            create_dir(Path::new(&test_dir)).unwrap();
        }
    }

    #[test]
    fn test_key_creation() {
        setup_test();
        let pub_name = "test.tmp/pubtest.pkcs7.pem";
        let priv_name = "test.tmp/privtest.pkcs7.pem";
        create_keys(&pub_name, &priv_name);

        //        // Verify cert is signed by key
        //        let pub_key_file = File::open(&pub_name).unwrap();
        //        let mut pub_reader = BufReader::new(pub_key_file);
        //        let priv_key_file = File::open(&priv_name).unwrap();
        //        let mut priv_reader = BufReader::new(priv_key_file);
        //        let mut pub_contents = Vec::new();
        //        let mut priv_contents = Vec::new();
        //        pub_reader.read_to_end(&mut pub_contents).unwrap();
        //        priv_reader.read_to_end(&mut priv_contents).unwrap();
        //
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

    #[test]
    fn encrypt_decrypt() {
        setup_test();
        let pub_name = "test.tmp/pubtest.pkcs7.pem";
        let priv_name = "test.tmp/privtest.pkcs7.pem";
        create_keys(&pub_name, &priv_name);

        let test_string = "abcd1234";
        let cipherstring = encrypt_str(&pub_name, test_string.clone().as_bytes(), &false);
        assert_eq!(
            test_string,
            from_utf8(&decrypt_str(
                &pub_name,
                &priv_name,
                &cipherstring.as_ref().to_pem().unwrap(),
                &false
            ))
            .unwrap()
        );
    }

    // Try to load file that doesn't exist
    #[test]
    #[should_panic]
    fn read_nonexistant_file() {
        read_file_contents("/totally/not/real/file/path").unwrap();
    }

    #[test]
    #[should_panic]
    fn parse_bad_x509() {
        setup_test();
        let bad_file_path = "test.tmp/badx509.pem";
        let mut bad_file = File::create(&bad_file_path).unwrap();
        bad_file
            .write_all("This is bad formatting".as_bytes())
            .unwrap();

        load_x509_file(&bad_file_path);
    }

    #[test]
    #[should_panic]
    fn encrypt_with_missing_key() {
        let input_array: [u8; 0] = [];
        encrypt_str("/totally/not/real/file/path", &input_array, &false);
        return ();
    }
    // todo: switch to something like speculate.rs for test teardown support
    //  (aka delete some of these files that are used)
}

fn read_file_contents(file_path: &str) -> std::io::Result<Vec<u8>> {
    let file_obj = File::open(&file_path)?;
    let mut file_reader = BufReader::new(file_obj);
    let mut file_contents = Vec::new();
    file_reader.read_to_end(&mut file_contents)?;
    Ok(file_contents)
}

// Change to return result object
fn load_rsa_file_private(private_key_filename: &str) -> Rsa<Private> {
    let priv_contents: Vec<u8> = read_file_contents(private_key_filename)
        .expect("There was an error reading the contents of the private key!");

    let priv_key = Rsa::private_key_from_pem(&priv_contents)
        .expect("There was an error parsing the private key!");
    return priv_key;
}

// Change to return result object
fn load_x509_file(public_key_filename: &str) -> X509 {
    let pub_contents: Vec<u8> = read_file_contents(public_key_filename)
        .expect("There was an error reading the contents of the public key!");
    let pub_key: X509 =
        X509::from_pem(&pub_contents).expect("There was an error parsing the public key!");
    return pub_key;
}

//todo return Pkcs7
fn encrypt_str(
    public_key_filename: &str,
    plaintext: &[u8],
    verbose: &bool,
) -> openssl::pkcs7::Pkcs7 {
    if verbose.clone() {
        println!("Using public key: {}", &public_key_filename);
    }
    let encryption_algo: Cipher = Cipher::aes_256_cbc();
    let cert_content = load_x509_file(public_key_filename);
    let mut cert_stack = Stack::new().expect("There was an error creating a new cert stack");
    cert_stack
        .push(cert_content)
        .expect("There was an error pushing the cert to the cert stack");
    let encrypted_pkcs7 = Pkcs7::encrypt(
        cert_stack.as_ref(),
        plaintext,
        encryption_algo,
        Pkcs7Flags::empty(),
    )
    .expect("There was an error encrypting the value!");
    if verbose.clone() {
        print! {"New ciphertext: "}
    }
    println!(
        "{:#}",
        from_utf8(&encrypted_pkcs7.as_ref().to_pem().unwrap()).unwrap()
    );
    return encrypted_pkcs7;
}

fn decrypt_str(
    public_key_filename: &str,
    private_key_filename: &str,
    pkcs7_ciphertext: &[u8],
    verbose: &bool,
) -> Vec<u8> {
    let priv_key = load_rsa_file_private(private_key_filename);
    let pub_cert = load_x509_file(public_key_filename);
    let cipher_content = Pkcs7::from_pem(pkcs7_ciphertext).expect(&format!(
        "Unable to parse PKCS7 from: {:?}",
        from_utf8(&pkcs7_ciphertext).unwrap()
    ));

    let decrypted_content = cipher_content
        .decrypt(
            PKey::from_rsa(priv_key).unwrap().as_ref(),
            pub_cert.as_ref(),
            Pkcs7Flags::empty(),
        )
        .unwrap();
    if verbose.clone() {
        print!("Decrypted content: ")
    }
    println!("{:}", from_utf8(decrypted_content.as_ref()).unwrap());
    return decrypted_content;
}

fn create_keys(public_key_filename: &str, private_key_filename: &str) {
    // Basically doing the same as this openssl command
    // openssl req -x509 -nodes -days 100000 -newkey rsa:2048 -keyout privatekey.pem -out publickey.pem -subj '/'

    // Create RSA private key
    let private_key = Rsa::generate(2048).expect("There was an error generating a new RSA key");

    // Generate cert and sign

    let mut x509 = X509Builder::new().expect("There was an error initializing the X509 builder.");

    // Create ref for our timeperiod
    let not_after = Asn1Time::days_from_now(100000).expect("Unable to get Asn1Time + 10000 days");
    x509.set_not_after(&not_after)
        .expect("Unable to set expiry on cert");
    x509.set_not_before(
        Asn1Time::days_from_now(0)
            .expect("Error setting validity date on cert")
            .as_ref(),
    )
    .unwrap();

    // Build our name
    let mut x509_name = X509NameBuilder::new().expect("Error initializing X509NameBuilder");
    x509_name
        .append_entry_by_text("CN", "/")
        .expect("Error adding CN to cert");
    let x509_name = x509_name.build();
    x509.set_subject_name(&x509_name)
        .expect("Error setting subject name on cert");
    x509.set_version(2).expect("Error setting X509 version");
    x509.set_pubkey(&PKey::from_rsa(private_key.clone()).unwrap())
        .unwrap();
    x509.sign(
        PKey::from_rsa(private_key.clone()).unwrap().as_ref(),
        MessageDigest::sha256(),
    )
    .expect("Error signing X509 certificate");
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
    // print the paths that the keys were generated at
    println!("Keys generated and written to files!")
}

fn open_editor(yaml_path: &str) {
    // Have this try common editors otherwise
    let editor: String = match var("EDITOR") {
        Ok(editor) => editor.clone(),
        Err(_) => "vim".to_string(),
    };
    let src_yaml_path = Path::new(yaml_path);
    if !src_yaml_path.exists()
        || !([OsStr::new("yaml"), OsStr::new("yml")].contains(
            &src_yaml_path
                .extension()
                .unwrap_or_else(|| OsStr::new("nothing")),
        ))
    {
        println!("{} does not appear to be a valid YAML file.", &yaml_path);
        exit(1);
    }

    //the path of the unencrypted file
    let unencrypted_file = NamedTempFile::new().unwrap_or_else(|e| {
        println!("Could not create temp file at {}", e);
        exit(1);
    });

    // Unencrypt file
    // todo

    Command::new(editor)
        .arg(&unencrypted_file.path())
        .status()
        .expect("Something went wrong");
}

// Maybe this isn't the right way to do this
fn create_keys_cli() -> u8 {
    return 0;
}

fn main() {
    let cli_yaml = load_yaml!("cli.yaml");
    let args = App::from(cli_yaml).get_matches();

    let verbose = match args.value_of("verbose") {
        Some(_) => true,
        None => false,
    };
    // Flow for different subcommands
    match args.subcommand() {
        ("createkeys", Some(createkeys_args)) => {
            //println!("createkeys was specified.");

            let public_key_path = match createkeys_args.value_of("public-key-path") {
                Some(words) => words,
                None => "keys/public_key.pkcs7.pem",
            };
            let private_key_path = match createkeys_args.value_of("private-key-path") {
                Some(words) => words,
                None => "keys/private_key.pkcs7.pem",
            };
            create_keys(public_key_path, private_key_path);
        }
        ("decrypt", Some(decrypt_args)) => {
            let mut file_supplied = false;
            let mut string_to_decrypt = match args.value_of("string") {
                Some(words) => words,
                None => "",
            };
            println!("{}", &string_to_decrypt);
            let public_key_path = match decrypt_args.value_of("public-key-path") {
                Some(words) => words,
                None => "keys/public_key.pkcs7.pem",
            };
            let private_key_path = match decrypt_args.value_of("private-key-path") {
                Some(words) => words,
                None => "keys/private_key.pkcs7.pem",
            };
            let file_to_decrypt: String = match decrypt_args.value_of("file") {
                Some(file) => {
                    file_supplied = true;
                    match read_to_string(&file) {
                        Ok(file_contents) => file_contents.to_owned(),
                        Err(_) => String::from("Hello world!"),
                    }
                }
                None => String::from("Hello World!"),
            };
            if file_supplied {
                string_to_decrypt = file_to_decrypt.as_ref();
            }
            decrypt_str(
                public_key_path,
                private_key_path,
                string_to_decrypt.as_bytes(),
                &verbose,
            );
        }
        ("encrypt", Some(encrypt_args)) => {
            let mut file_supplied = false;
            let mut string_to_encrypt = match encrypt_args.value_of("string") {
                Some(words) => words,
                None => "Hello World!",
            };
            let public_key_path = match encrypt_args.value_of("public-key-path") {
                Some(words) => words,
                None => "keys/public_key.pkcs7.pem",
            };

            let file_to_encrypt: String = match encrypt_args.value_of("file") {
                Some(file) => {
                    file_supplied = true;
                    match read_to_string(&file) {
                        Ok(file_contents) => file_contents.to_owned(),
                        Err(_) => String::from("Hello world!"),
                    }
                }
                None => String::from("Hello World!"),
            };
            if file_supplied {
                string_to_encrypt = file_to_encrypt.as_ref();
            }
            encrypt_str(public_key_path, &string_to_encrypt.as_bytes(), &verbose);
        }
        ("recrypt", Some(recrypt_args)) => {
            println!("This is not implemented yet.");
            unimplemented!();
        }
        ("rekey", Some(rekey_args)) => {
            println!("This is not implemented yet.");
            unimplemented!();
        }
        ("edit", Some(edit_args)) => {
            let input_file = match edit_args.value_of("file") {
                Some(f) => f,
                None => "Test123",
            };
            open_editor(&input_file);
        }
        ("", none_args) => {
            println!("No subcommand was specified.");
            println!("{}", args.usage());
        }
        _ => {
            println!("Unknown subcommand specified");
            println!("{}", args.usage());
        }
    }

    //println!("Args: {:#?}", args);
}
