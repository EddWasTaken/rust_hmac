use std::time::{Instant};
use sha2::Sha256;
use hmac::{Hmac, Mac};

// alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

fn main() {

    let char_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzÀÁÂÃÇÈÉÊÌÍÒÓÔÕÙÚÛàáâãçèéêìíîòóôõùúû";
    let base_hash = "c10c9a974e996434bea17305fb3207fe283b94dc4e808a7ec54ca86b5a62744b";

    let start = Instant::now();

    for i in 1000..9999 {
        for j in char_set.chars() {
            for k in char_set.chars() {

                // formatting key and secret
                let mut key = String::from(j);
                let secret = i.to_string();
                key.push(k);

                // hashing 
                let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
                mac.update(&secret.as_bytes());
                let result = mac.finalize();
                // formatting result into bytes and then into hex string
                let result_bytes = result.into_bytes();
                let result_hex = hex::encode(result_bytes);
                if result_hex == base_hash {
                    let duration = start.elapsed();
                    println!("Hash matched!\nIt took {:?}.\nKey: {}\nSecret: {}",duration , key, secret);
                    return;
                }
            }
        }
    }
    let duration = start.elapsed();
    println!("Couldn't brute force the hash in {:?}.", duration);
    return;
}
