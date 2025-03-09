use anyhow::Result;
use clap::{Parser, Subcommand};
use color_print::cprintln;
use cript::config::{CriptConfig, PasswordConfig};
use cript::secret::passwd_to_public_key_base64;
use cript::{decrypt_blocks, encrypt_blocks, get_encrypted_blocks, get_plain_text_blocks};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage keys
    Keys {
        #[command(subcommand)]
        subcommand: KeysCommands,
    },
    /// Encrypt the Cript Block(Plain text) in all cript files under the path
    Encrypt { path: Option<PathBuf> },
    /// Decrypt the Cript Block(Encrypted) in all cript files under the path
    Decrypt { path: Option<PathBuf> },
    /// Show encryption status of files under the path
    Status { path: Option<PathBuf> },
    /// Check if all files under the path are fully encrypted
    Check { path: Option<PathBuf> },
}

#[derive(Subcommand)]
enum KeysCommands {
    /// List all keys
    List,
    /// Set a key through password
    Set { key_id: String, password: String },
    /// Remove a key
    Rm { key_id: String },
    /// Verify a key with a password
    Verify { key_id: String, password: String },
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
                }
                KeysCommands::Set { key_id, password } => {
                    // 生成公钥并设置
                    let public_key = passwd_to_public_key_base64(&password);
                    config.set_key(&key_id, &public_key);
                    // 保存配置
                    config.save(std::env::current_dir().unwrap())?;
                    println!("已设置密钥 {key_id}: {public_key}");
                }
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
        }
        Commands::Encrypt { path } => {
            let path = path.unwrap_or(PathBuf::from("./"));
            let files = get_cript_files(&path, &config)?
                .into_iter()
                .filter_map(|path| {
                    let content = fs::read_to_string(&path).unwrap();
                    let blocks = get_plain_text_blocks(&content);
                    if blocks.is_empty() {
                        None
                    } else {
                        Some((path, blocks))
                    }
                })
                .collect::<Vec<_>>();
            if files.is_empty() {
                println!("no plain text block found");
            } else {
                for (path, blocks) in files {
                    print!(
                        "encrypting {} plain text blocks in {path:?}...",
                        blocks.len()
                    );
                    encrypt_file(&path, &config)?;
                    println!("done")
                }
            }
        }
        Commands::Decrypt { path } => {
            let path = path.unwrap_or(PathBuf::from("./"));
            let password_config = PasswordConfig::from_env();
            let files = get_cript_files(&path, &config)?
                .into_iter()
                .filter_map(|path| {
                    let content = fs::read_to_string(&path).unwrap();
                    let blocks = get_encrypted_blocks(&content);
                    if blocks.is_empty() {
                        None
                    } else {
                        Some((path, blocks))
                    }
                })
                .collect::<Vec<_>>();
            if files.is_empty() {
                println!("no encrypted block found");
            } else {
                for (path, blocks) in files {
                    print!(
                        "decrypting {} encrypted blocks in {path:?}...",
                        blocks.len()
                    );
                    decrypt_file(&path, &password_config)?;
                    println!("done")
                }
            }
        }
        Commands::Status { path } => {
            let path = path.unwrap_or(PathBuf::from("./"));
            let files = get_cript_files(&path, &config)?;

            // 分类文件
            let mut files_with_plain_text = Vec::new();
            let mut fully_encrypted_files = Vec::new();

            for file_path in files {
                let content = fs::read_to_string(&file_path).unwrap();
                let plain_blocks = get_plain_text_blocks(&content);
                let encrypted_blocks = get_encrypted_blocks(&content);

                if !plain_blocks.is_empty() && !encrypted_blocks.is_empty() {
                    // 同时包含明文和密文块
                    files_with_plain_text.push((
                        file_path,
                        plain_blocks.len(),
                        encrypted_blocks.len(),
                    ));
                } else if !plain_blocks.is_empty() {
                    // 只包含明文块
                    files_with_plain_text.push((file_path, plain_blocks.len(), 0));
                } else if !encrypted_blocks.is_empty() {
                    // 只包含密文块
                    fully_encrypted_files.push((file_path, encrypted_blocks.len()));
                }
            }

            // 输出状态信息
            println!("Cript Status:");

            if files_with_plain_text.is_empty() {
                println!("Nothing to encrypt, working space clean")
            }

            if !files_with_plain_text.is_empty() {
                println!("\nFiles not fully encrypted:");
                for (path, plain_count, encrypted_count) in &files_with_plain_text {
                    cprintln!(
                        "  <r>{}</r>:\t<r>{} plain</r>/<g>{} encrypted</g>/{} total",
                        path.display(),
                        plain_count,
                        encrypted_count,
                        plain_count + encrypted_count,
                    );
                }
            }

            if !fully_encrypted_files.is_empty() {
                println!("\nFully encrypted files:");
                for (path, count) in &fully_encrypted_files {
                    cprintln!("  {}: {} encrypted blocks", path.display(), count);
                }
            }
        }
        Commands::Check { path } => {
            let path = path.unwrap_or(PathBuf::from("./"));
            let files = get_cript_files(&path, &config)?;

            let mut unencrypted_files = Vec::new();

            for file_path in files {
                let content = fs::read_to_string(&file_path).unwrap();
                let plain_blocks = get_plain_text_blocks(&content);

                if !plain_blocks.is_empty() {
                    unencrypted_files.push((file_path, plain_blocks.len()));
                }
            }

            if !unencrypted_files.is_empty() {
                println!("There are {} files not fully encrypted", unencrypted_files.len());
                for (path, count) in &unencrypted_files {
                    cprintln!("  <r>{}</r>: {} plain text blocks", path.display(), count);
                }
                return Err(anyhow::anyhow!("Not fully encrypted"));
            } else {
                println!("Nothing to encrypt, working space clean");
            }
        }
    }

    Ok(())
}

fn get_cript_files(path: &Path, config: &CriptConfig) -> Result<Vec<PathBuf>> {
    Ok(if path.is_file() {
        if config.extensions.is_empty()
            || path
                .extension()
                .map(|s| config.extensions.contains(&s.to_str().unwrap().to_string()))
                .unwrap_or(false)
        {
            vec![path.to_path_buf()]
        } else {
            vec![]
        }
    } else {
        let mut patterns = vec![];
        for ext in &config.extensions {
            patterns.push(format!("**/*.{ext}"));
        }
        if patterns.is_empty() {
            patterns.push("**/*".to_string());
        }
        for exclude in &config.excludes {
            patterns.push(format!("!{exclude}"));
        }
        globwalk::GlobWalkerBuilder::from_patterns(path, &patterns)
            .build()?
            .filter_map(Result::ok)
            .map(|entry| entry.path().to_path_buf())
            .collect()
    })
}

fn encrypt_file(path: impl AsRef<Path>, config: &CriptConfig) -> Result<()> {
    let content = std::fs::read_to_string(&path)?;
    fs::write(&path, encrypt_blocks(&content, config)?)?;
    Ok(())
}

fn decrypt_file(path: impl AsRef<Path>, password_config: &PasswordConfig) -> Result<()> {
    let content = std::fs::read_to_string(&path)?;
    fs::write(path, decrypt_blocks(&content, password_config)?)?;
    Ok(())
}
