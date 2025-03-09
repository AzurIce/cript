use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use cript::config::{CriptConfig, PasswordConfig};
use cript::secret::passwd_to_public_key_base64;
use cript::{decrypt_file, encrypt_file, is_cript_path};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 管理密钥
    Keys {
        #[command(subcommand)]
        subcommand: KeysCommands,
    },
    /// 加密.cript文件中的标签内容
    Encrypt {
        /// 要加密的.cript文件路径
        path: PathBuf,
    },
    /// 解密文件中的加密内容
    Decrypt {
        /// 要解密的文件路径
        path: PathBuf,
    },
    /// 输入密钥生成公钥
    GenPublicKey { password: String },
}

#[derive(Subcommand)]
enum KeysCommands {
    /// 列出所有密钥
    List,
    /// 设置密钥
    Set {
        /// 密钥ID
        key_id: String,
        /// 密码
        password: String,
    },
    /// 删除密钥
    Rm {
        /// 密钥ID
        key_id: String,
    },
    Verify {
        /// 密钥ID
        key_id: String,
        /// 密码
        password: String,
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 加载配置文件
    let mut config = CriptConfig::load(std::env::current_dir().unwrap())?;

    match cli.command {
        Commands::Keys { subcommand } => {
            match subcommand {
                KeysCommands::List => {
                    // 列出所有密钥
                    println!("找到 {} 个密钥:", config.keys.len());
                    for id in config.keys.keys() {
                        println!(
                            "{id}({})： {}",
                            config.get_name(id).unwrap(),
                            config.get_public_key_base64(id).unwrap()
                        );
                    }
                },
                KeysCommands::Set { key_id, password } => {
                    // 生成公钥并设置
                    let public_key = passwd_to_public_key_base64(&password);
                    config.set_key(&key_id, &public_key);
                    // 保存配置
                    config.save(std::env::current_dir().unwrap())?;
                    println!("已设置密钥 {key_id}: {public_key}");
                },
                KeysCommands::Rm { key_id } => {
                    // 删除密钥
                    if config.remove_key(&key_id) {
                        // 保存配置
                        config.save(std::env::current_dir().unwrap())?;
                        println!("已删除密钥 {key_id}");
                    } else {
                        println!("密钥 {key_id} 不存在");
                    }
                }
                KeysCommands::Verify { key_id, password } => {
                    let public_key = config.get_public_key(&key_id).unwrap();
                    let secret_key = cript::secret::passwd_to_secret_key(&password);
                    if public_key == ecies_ed25519::PublicKey::from_secret(&secret_key) {
                        println!("密钥 {key_id} 验证通过");
                    } else {
                        println!("密钥 {key_id} 验证失败");
                    }
                }
            }
        },
        Commands::Encrypt { path } => {
            if !is_cript_path(&path) {
                return Err(anyhow!("不是cript文件"));
            }
            encrypt_file(&path, &config)?;
            fs::remove_file(&path)?;
        },
        Commands::Decrypt { path } => {
            let password_config = PasswordConfig::from_env();
            decrypt_file(&path, &password_config).unwrap();
            fs::remove_file(&path)?;
        },
        Commands::GenPublicKey { password } => {
            println!("{}", passwd_to_public_key_base64(&password))
        }
    }

    Ok(())
}
