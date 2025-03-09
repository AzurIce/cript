use base64::Engine;
use ecies_ed25519::{PublicKey, SecretKey};
use sha2::{Sha512, Digest};
use anyhow::{anyhow, Result};

pub fn passwd_to_secret_key(passwd: &str) -> SecretKey {
    // 对密码进行 SHA512 哈希
    let mut hasher = Sha512::new();
    hasher.update(passwd.as_bytes());
    let hash = hasher.finalize();

    // 使用哈希值的前32字节作为 ed25519 密钥
    SecretKey::from_bytes(&hash[..32]).unwrap()
}

pub fn passwd_to_public_key_base64(passwd: &str) -> String {
    let secret = passwd_to_secret_key(passwd);
    // 从私钥生成公钥, 并转换为 base64 编码
    PublicKey::from_secret(&secret).into()
}

/// 解密字符串
/// - `content`: 加密后以 base64 编码的字符串
pub fn decrypt_str(content: &str, secret_key: &SecretKey) -> Result<String> {
    // 将Base64编码的内容解码为字节
    let encrypted_bytes = base64::prelude::BASE64_STANDARD
        .decode(content)
        .map_err(|e| anyhow!("Base64解码失败: {}", e))?;

    // 解密内容
    let decrypted_bytes = ecies_ed25519::decrypt(secret_key, &encrypted_bytes)
        .map_err(|e| anyhow!("解密失败: {}", e))?;

    // 将解密后的字节转换为字符串
    let decrypted_text =
        String::from_utf8(decrypted_bytes).map_err(|e| anyhow!("解码UTF-8失败: {}", e))?;

    Ok(decrypted_text)
}

/// 加密字符串，加密后以base64编码
/// - `content`: 待加密的字符串
pub fn encrypt_str(content: &str, public_key: &PublicKey) -> Result<String> {
    // 加密内容
    let mut csprng = rand::thread_rng();
    let encrypted_bytes = ecies_ed25519::encrypt(&public_key, content.as_bytes(), &mut csprng)
        .map_err(|e| anyhow!("加密失败: {}", e))?;

    // 将加密后的内容转换为Base64编码
    let encrypted_base64 = base64::prelude::BASE64_STANDARD.encode(&encrypted_bytes);
    Ok(encrypted_base64)
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_gen_key() {
        let key = passwd_to_public_key_base64("password");
        assert_eq!("zAQynvCR0krsKwiZDjMYxVtcgkd5csKaD83FsyDRT98=", key.as_str())
    }
}