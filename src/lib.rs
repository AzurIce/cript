use anyhow::Result;
use config::{CriptConfig, PasswordConfig};
use regex::{Captures, Regex};
use secret::{decrypt_str, encrypt_str};

pub mod config;
pub mod secret;

pub enum CriptBlock {
    PlainText(PlainTextBlock),
    EncryptedBlock(EncryptedBlock),
}
pub struct PlainTextBlock {
    key_id: String,
    content: String,
}

impl PlainTextBlock {
    pub fn new(key_id: String, content: String) -> Self {
        Self { key_id, content }
    }
    pub fn encrypt(self, config: &CriptConfig) -> Result<EncryptedBlock> {
        Ok(EncryptedBlock {
            content: encrypt_str(&self.content, &config.get_public_key(&self.key_id)?)?,
            key_id: self.key_id,
        })
    }
    pub fn get_block_string(&self) -> String {
        if &self.key_id == "default" {
            format!("{{cript}}{}{{/cript}}", self.content)
        } else {
            format!("{{cript={}}}{}{{/cript}}", self.key_id, self.content)
        }
    }
}

pub struct EncryptedBlock {
    key_id: String,
    content: String,
}

impl EncryptedBlock {
    pub fn new(key_id: String, content: String) -> Self {
        Self { key_id, content }
    }
    pub fn decrypt(self, password_config: &PasswordConfig) -> Result<PlainTextBlock> {
        Ok(PlainTextBlock {
            content: decrypt_str(
                &self.content,
                &password_config.get_secret_key(&self.key_id)?,
            )?,
            key_id: self.key_id,
        })
    }
    pub fn get_block_string(&self) -> String {
        if &self.key_id == "default" {
            format!("{{cript,{}/}}", self.content)
        } else {
            format!("{{cript={},{}/}}", self.key_id, self.content)
        }
    }
}

const PLAIN_TEXT_RE: &str = r"\{cript(?:=([\w\-_]+))?\}([^{]+)\{\/cript\}";
const ENCRYPTED_RE: &str = r"\{cript(?:=([\w\-_]+))?,(.+?)\/\}";

pub fn encrypt_blocks(content: &str, config: &CriptConfig) -> Result<String> {
    // 创建正则表达式匹配 {cript} 或 {cript=key-id} 格式的标签及其内容
    let re = Regex::new(PLAIN_TEXT_RE).unwrap();
    // 使用替换功能，对每个匹配项进行处理
    replace_all(&re, &content, |caps: &regex::Captures| -> Result<String> {
        // 获取密钥名称，如果没有指定则使用 "default"
        let key_id = caps.get(1).map_or("default", |s| s.as_str()).to_string();
        let content = caps[2].to_string();

        let block = PlainTextBlock::new(key_id, content).encrypt(config);

        block.map(|block| block.get_block_string())
    })
}

pub fn decrypt_blocks(content: &str, password_config: &PasswordConfig) -> Result<String> {
    // 创建正则表达式匹配新格式的加密内容
    let re = Regex::new(ENCRYPTED_RE).unwrap();

    // 使用替换功能，对每个匹配项进行处理
    replace_all(&re, &content, |caps: &regex::Captures| -> Result<String> {
        // 获取密钥名称，如果没有指定则使用 "default"
        let key_id = caps.get(1).map_or("default", |m| m.as_str()).to_string();
        let content = caps[2].to_string();

        let block = EncryptedBlock::new(key_id, content).decrypt(password_config);

        block.map(|block| block.get_block_string())
    })
}

pub fn get_plain_text_blocks(content: &str) -> Vec<PlainTextBlock> {
    let plain_text_re = Regex::new(PLAIN_TEXT_RE).unwrap();
    let mut blocks = Vec::new();
    for caps in plain_text_re.captures_iter(content) {
        let key_id = caps.get(1).map_or("default", |m| m.as_str()).to_string();
        let content = caps[2].to_string();
        blocks.push(PlainTextBlock::new(key_id, content));
    }

    blocks
}

pub fn get_encrypted_blocks(content: &str) -> Vec<EncryptedBlock> {
    let mut blocks = Vec::new();
    let encrypted_re = Regex::new(ENCRYPTED_RE).unwrap();
    for caps in encrypted_re.captures_iter(content) {
        let key_id = caps.get(1).map_or("default", |m| m.as_str()).to_string();
        let content = caps[2].to_string();
        blocks.push(EncryptedBlock::new(key_id, content));
    }
    blocks
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
