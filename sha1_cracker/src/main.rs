use sha1::Digest;
use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
};

const SHA1_HEX_STRING_LENGTH: usize = 40;

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let hash_to_crack = validate_hash(&args)?;
    let wordlist_file = File::open(&args[1])?;
    let reader = BufReader::new(&wordlist_file);
    crack_password(reader, &hash_to_crack)
}

fn parse_args() -> Result<Vec<String>, Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Usage:");
        println!("sha1_cracker: <wordlist.txt> <sha1_hash>");
        Err("Invalid number of arguments".into())
    } else {
        Ok(args)
    }
}

fn validate_hash(args: &[String]) -> Result<String, Box<dyn Error>> {
    let hash_to_crack = args[2].trim();
    if hash_to_crack.len() != SHA1_HEX_STRING_LENGTH {
        Err("sha1 hash is not valid".into())
    } else {
        Ok(hash_to_crack.to_string())
    }
}

fn crack_password(reader: BufReader<&File>, hash_to_crack: &String) -> Result<(), Box<dyn Error>> {
    for line in reader.lines() {
        let line = line?;
        let common_password = line.trim();
        if hash_to_crack == &hex::encode(sha1::Sha1::digest(common_password.as_bytes())) {
            println!("Password found: {}", &common_password);
            return Ok(());
        }
    }

    println!("password not found in wordlist :(");
    Ok(())
}
