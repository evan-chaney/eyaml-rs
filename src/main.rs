extern crate yaml_rust;
use clap::{load_yaml, App};

fn main() {
    let cli_matches = App::from(load_yaml!("cli.yaml")).get_matches();
}
