use anyhow::{Context, Result, anyhow};
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

// MARK: CriptConfig

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
        PublicKey::try_from(public_key_base64).map_err(|e| anyhow!("无法解码公钥: {}", e))
    }
    pub fn get_name(&self, id: &str) -> Option<String> {
        self.keys
            .get(id)
            .and_then(|entry| entry.name().map(|s| s.to_string()).or(Some(id.to_string())))
    }
    /// 加载并解析cript.toml文件
    pub fn load(start_dir: impl AsRef<Path>) -> Result<Self> {
        let start_dir = start_dir.as_ref();
        let config_path = find_config_in_ancestors(&start_dir)?;

        let config_content = fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;

        // 使用serde直接解析TOML
        let config = toml::from_str::<Self>(&config_content)
            .with_context(|| format!("Failed to parse TOML in {}", config_path.display()))?;

        Ok(config)
    }
    
    /// 保存配置到文件
    pub fn save(&self, start_dir: impl AsRef<Path>) -> Result<()> {
        let start_dir = start_dir.as_ref();
        let config_path = find_config_in_ancestors(&start_dir)?;
        
        let toml_content = toml::to_string(self)
            .with_context(|| "Failed to serialize config to TOML")?;
            
        fs::write(&config_path, toml_content)
            .with_context(|| format!("Failed to write config file: {}", config_path.display()))?;
            
        Ok(())
    }
    
    /// 设置密钥
    pub fn set_key(&mut self, key_id: &str, public_key: &str) {
        self.keys.insert(key_id.to_string(), KeyEntry::Simple(public_key.to_string()));
    }
    
    /// 删除密钥
    pub fn remove_key(&mut self, key_id: &str) -> bool {
        self.keys.remove(key_id).is_some()
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

// MARK: PasswordConfig

/// 表示密码配置，从环境变量中读取
#[derive(Debug, Default)]
pub struct PasswordConfig {
    /// 存储密码的映射，key 为 key-id，value 为对应的密码
    passwords: HashMap<String, String>,
}

impl PasswordConfig {
    /// 创建一个新的 PasswordConfig 实例，从环境变量中读取配置 `cript_<key-id> = password`
    pub fn from_env() -> Self {
        let mut config = PasswordConfig::default();
        
        // 遍历所有环境变量
        for (key, value) in std::env::vars() {
            // 检查是否以 cript_ 开头
            if let Some(key_id) = key.strip_prefix("cript_") {
                config.passwords.insert(key_id.to_string(), value);
            }
        }
        
        config
    }

    /// 获取指定 key-id 对应的密码
    pub fn get_password(&self, key_id: &str) -> Option<&str> {
        self.passwords.get(key_id).map(|s| s.as_str())
    }
}
