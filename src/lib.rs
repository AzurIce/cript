use ecies_ed25519::{PublicKey, SecretKey};
use sha2::{Sha512, Digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
pub mod config;

pub fn passwd_to_secret_key(passwd: &str) -> SecretKey {
    // 对密码进行 SHA512 哈希
    let mut hasher = Sha512::new();
    hasher.update(passwd.as_bytes());
    let hash = hasher.finalize();

    // 使用哈希值的前32字节作为 ed25519 密钥
    SecretKey::from_bytes(&hash[..32]).unwrap()
}

pub fn gen_key(passwd: &str) -> String {
    // 使用哈希值的前32字节作为 ed25519 密钥
    let secret = passwd_to_secret_key(passwd);
    // 从私钥生成公钥
    let public = PublicKey::from_secret(&secret);
    // 对公钥进行 base64 编码
    BASE64.encode(public.as_bytes())
}

#[cfg(test)]
mod test {
    use crate::gen_key;

    #[test]
    fn test_gen_key() {
        let key = gen_key("password");
        assert_eq!("zAQynvCR0krsKwiZDjMYxVtcgkd5csKaD83FsyDRT98=", key.as_str())
    }
}