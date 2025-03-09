use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use config::{CriptConfig, PasswordConfig};
use regex::{Captures, Regex};
use secret::{decrypt_str, encrypt_str, passwd_to_secret_key};

pub mod config;
pub mod secret;

/// 去掉 cript
pub fn get_encrypt_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();

    let encrypt_path = path.with_extension("");
    if encrypt_path.extension().is_none() {
        encrypt_path
    } else {
        encrypt_path.with_extension(path.extension().unwrap_or(OsStr::new("")))
    }
}

/// filename.cript or filename.xxx.cript.yyy
pub fn is_cript_path(path: impl AsRef<Path>) -> bool {
    let filename = path.as_ref().file_name().and_then(|s| s.to_str()).unwrap();
    let extensions = filename.split(".").skip(1).collect::<Vec<_>>();
    if extensions.len() == 1 && extensions[0] == "cript"
        || extensions.len() > 1 && extensions[extensions.len() - 2] == "cript"
    {
        true
    } else {
        false
    }
}

/// 添加 cript
pub fn get_decrypt_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();

    let extension = path
        .extension()
        .map(|ext| format!(".{}", ext.to_str().unwrap()))
        .unwrap_or(String::new());
    path.with_extension(format!("cript{extension}"))
}

pub fn encrypt_file(path: impl AsRef<Path>, config: &CriptConfig) -> Result<()> {
    let path = path.as_ref();

    let content = std::fs::read_to_string(path)?;

    // 创建正则表达式匹配 {cript} 或 {cript=key-id} 格式的标签及其内容
    let re = Regex::new(r"(\{cript(?:=([^}]+))?\})([^{]+)(\{\/cript\})").unwrap();

    // 使用替换功能，对每个匹配项进行处理
    let result = re.replace_all(&content, |caps: &regex::Captures| {
        // 获取开始标签
        let start_tag = &caps[1];
        // 获取结束标签
        let end_tag = &caps[4];
        // 获取密钥名称，如果没有指定则使用 "default"
        let key_name = caps.get(2).map_or("default", |m| m.as_str());
        let plain_text = &caps[3];

        let public_key = config.get_public_key(key_name).unwrap();

        // 使用密码解密内容
        match encrypt_str(plain_text, &public_key) {
            Ok(encrypted) => format!("{}{}{}", start_tag, encrypted, end_tag),
            Err(e) => {
                // 在实际应用中，你可能需要更好地处理错误
                panic!("{}{}{}{}{}", start_tag, "[解密错误: ", e, "]", end_tag)
            }
        }
    });

    // println!("{:?} {:?}", get_encrypt_path(path), result.to_string());
    fs::write(get_encrypt_path(path), result.to_string())?;

    Ok(())
}

fn replace_all<E>(
    re: &Regex,
    haystack: &str,
    replacement: impl Fn(&Captures) -> Result<String, E>,
) -> Result<String, E> {
    let mut new = String::with_capacity(haystack.len());
    let mut last_match = 0;
    for caps in re.captures_iter(haystack) {
        let m = caps.get(0).unwrap();
        new.push_str(&haystack[last_match..m.start()]);
        new.push_str(&replacement(&caps)?);
        last_match = m.end();
    }
    new.push_str(&haystack[last_match..]);
    Ok(new)
}

pub fn decrypt_file(path: impl AsRef<Path>, password_config: &PasswordConfig) -> Result<()> {
    let path = path.as_ref();

    let content = std::fs::read_to_string(path)?;

    // 创建正则表达式匹配 {cript} 或 {cript=key-id} 格式的标签及其内容
    let re = Regex::new(r"(\{cript(?:=([^}]+))?\})([^{]+)(\{\/cript\})").unwrap();

    // 使用替换功能，对每个匹配项进行处理
    let result = replace_all(&re, &content, |caps: &regex::Captures| -> Result<String> {
        // 获取开始标签
        let start_tag = &caps[1];
        // 获取结束标签
        let end_tag = &caps[4];
        // 获取密钥名称，如果没有指定则使用 "default"
        let key_name = caps.get(2).map_or("default", |m| m.as_str());
        let encrypted_base64 = &caps[3];

        let secret_key =
            passwd_to_secret_key(password_config.get_password(key_name).ok_or(anyhow!(
                "找不到 {} 对应的密码，通过 cript_{} 环境变量来设置",
                key_name,
                key_name
            ))?);

        // 使用密码解密内容
        decrypt_str(encrypted_base64, &secret_key)
            .map(|decrypted| format!("{}{}{}", start_tag, decrypted, end_tag))
            .map_err(|err| anyhow!("{}{}{}{}{}", start_tag, "[dd解密错误: ", err, "]", end_tag))
    })?;

    fs::write(get_decrypt_path(path), result)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_path() {
        // 测试单一扩展名的文件
        let path = PathBuf::from("/path/to/file.txt");
        let decrypt_path = get_decrypt_path(&path);
        assert_eq!(decrypt_path, PathBuf::from("/path/to/file.cript.txt"));

        // 测试多个扩展名的文件
        let path = PathBuf::from("/path/to/file.tar.gz");
        let decrypt_path = get_decrypt_path(&path);
        assert_eq!(decrypt_path, PathBuf::from("/path/to/file.tar.cript.gz"));

        // 测试没有扩展名的文件
        let path = PathBuf::from("/path/to/file");
        let decrypt_path = get_decrypt_path(&path);
        assert_eq!(decrypt_path, PathBuf::from("/path/to/file.cript"));
    }
}
