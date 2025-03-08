use anyhow::{Context, Result, anyhow};
use base64::Engine;
use ecies_ed25519::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// 表示 Cript.toml 文件中的一个密钥条目
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyEntry {
    Simple(String),
    Full { name: Option<String>, value: String },
}

impl KeyEntry {
    pub fn value(&self) -> &str {
        match self {
            KeyEntry::Simple(key) => key,
            KeyEntry::Full { value: pub_key, .. } => pub_key,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            KeyEntry::Simple(_) => None,
            KeyEntry::Full { name, .. } => name.as_deref(),
        }
    }
}

/// 表示解析后的 Cript.toml 配置
#[derive(Debug, Serialize, Deserialize)]
pub struct CriptConfig {
    #[serde(default)]
    pub keys: HashMap<String, KeyEntry>,
}

impl CriptConfig {
    pub fn get_public_key_base64(&self, id: &str) -> Option<String> {
        self.keys.get(id).map(|entry| entry.value().to_string())
    }
    pub fn get_public_key(&self, id: &str) -> anyhow::Result<PublicKey> {
        let public_key_base64 = self
            .get_public_key_base64(id)
            .ok_or(anyhow!("公钥 {id} 不存在"))?;
        // Base64解码公钥
        let public_key_bytes = base64::prelude::BASE64_STANDARD
            .decode(&public_key_base64)
            .map_err(|e| anyhow!("无法解码公钥: {}", e))?;

        // 转换为ecies-ed25519库需要的公钥格式
        ecies_ed25519::PublicKey::from_bytes(&public_key_bytes)
            .map_err(|e| anyhow!("无效的公钥: {}", e))
    }
    pub fn get_name(&self, id: &str) -> Option<String> {
        self.keys
            .get(id)
            .and_then(|entry| entry.name().map(|s| s.to_string()).or(Some(id.to_string())))
    }
}

/// 在给定目录及其所有祖先目录中查找 Cript.toml 文件
fn find_config_in_ancestors(start_dir: &Path) -> Result<PathBuf> {
    let config_filename = "Cript.toml";
    let mut current_dir = start_dir.to_path_buf();

    loop {
        let config_path = current_dir.join(config_filename);

        if config_path.exists() {
            return Ok(config_path);
        }

        // 尝试移动到父目录
        if !current_dir.pop() {
            // 如果没有父目录了，则返回错误
            return Err(anyhow!(
                "Could not find '{}' in the current directory or any parent directories.",
                config_filename
            ));
        }
    }
}

/// 加载并解析cript.toml文件
pub fn load_config() -> Result<CriptConfig> {
    let current_dir = std::env::current_dir().context("Failed to get current directory")?;

    let config_path = find_config_in_ancestors(&current_dir)?;

    let config_content = fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;

    // 使用serde直接解析TOML
    let config: CriptConfig = toml::from_str(&config_content)
        .with_context(|| format!("Failed to parse TOML in {}", config_path.display()))?;

    Ok(config)
}
