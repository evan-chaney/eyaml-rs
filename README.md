# eyaml-rs
Rust port of the EYAML Ruby Gem. Work in progress!

## Installation

Simply run ```cargo install eyaml-rs``` to install from [crates.io](crates.io).
Otherwise you can build from source by running ```cargo build --release``` from the root of the repo. (Requires cargo be [installed](https://rustup.rs/)). This will create eyaml-rs at the `target/release/eyaml-rs`. This binary can be symlinked to a directory in your path to be invoked directly.

## Usage

### Create your keys
```
$ target/release/eyaml-rs createkeys
Keys generated and written to files!
```
If a custom path is not specified, the keys are generated in ./keys, which is also created.

### Encrypt a file
```
$ echo "Here is some text" > encrypt_me.txt
$ target/release/eyaml-rs encrypt -f encrypt_me.txt
-----BEGIN PKCS7-----
MIIBiQYJKoZIhvcNAQcDoIIBejCCAXYCAQAxggEhMIIBHQIBADAFMAACAQAwDQYJ
KoZIhvcNAQEBBQAEggEAh7lHWs2KeuoR8hU9b7B+iENK/6I3JWBwPVc49BySdokI
OhbkhdgPwqXGWE+GyEAP2wzhG1NfPf0C4srLIY9a0OM4u2b0QJuXePJtdezKJijE
nARCp7r4hUhPor4db5bkXizPrPo+g8dKp/MiRLbc5DZqWYSQ2E+SRKzrOQH7/aqC
Uwncqhsfaoq/BVDoiNDx2rFTwUyKlJsb5ofXga7UeYuG1hSkPs5diQoyYf///t0x
GYbxmyUPh8c9dI+jpUdabzJtEbfrW/KbDhPxxg6z+qn6xpJ/q3JPfsXT45TshHFc
rQ3cu3bH5WbtjRnRfXHrt6sUxuNtlUA+DNKP68/QjjBMBgkqhkiG9w0BBwEwHQYJ#
YIZIAWUDBAEqBBDDLWxWcaN4eYThBDf95V2ZgCDjNauNyW+C8IkJWqMunHt0kC4V
ZdZMVyiNVzh9Is/tBQ==
-----END PKCS7-----
```

### Decrypt a file
```
$ target/release/eyaml-rs decrypt -f decrypt_me.enc

Here is some text
```
