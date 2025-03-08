use anyhow::{Context, Result, anyhow};
use base64::{self, Engine};
use clap::{Parser, Subcommand};
use cript::config::load_config;
use ecies_ed25519;
use regex::Regex;
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
    /// 列出配置文件中的所有密钥
    List,
    /// 加密.cript文件中的标签内容
    Encode {
        /// 要加密的.cript文件路径
        path: PathBuf,
        /// 如果输出文件已存在，是否强制覆盖
        #[arg(short, long)]
        force: bool,
        /// 自定义输出文件路径
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// 解密文件中的加密内容
    Decode {
        /// 要解密的文件路径
        path: PathBuf,
        /// 如果输出文件已存在，是否强制覆盖
        #[arg(short, long)]
        force: bool,
        /// 自定义输出文件路径
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 加载配置文件
    let config = load_config()?;

    match cli.command {
        Commands::List => {
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
        Commands::Encode {
            path,
            force,
            output,
        } => {
            // 获取所有扩展名
            let extensions: Vec<_> = path
                .as_path()
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.split('.').skip(1).collect::<Vec<_>>())
                .unwrap_or_default();
            println!("{:?}", extensions);

            // 如果扩展名数量大于2（即有多个扩展名）
            if extensions.len() > 1 {
                // 检查倒数第二个扩展名是否为cript
                if extensions[extensions.len() - 2] != "cript" {
                    return Err(anyhow!("文件必须包含.cript后缀"));
                }
            } else if extensions.len() == 1 {
                // 只有一个扩展名时，检查是否为cript
                if extensions[0] != "cript" {
                    return Err(anyhow!("文件必须是.cript后缀"));
                }
            } else {
                return Err(anyhow!("文件必须是.cript后缀"));
            }

            // 读取文件内容
            let content = fs::read_to_string(&path)
                .map_err(|e| anyhow!("无法读取文件 {}: {}", path.display(), e))?;

            // 处理文件内容，加密标签中的内容
            let processed_content = process_cript_file(&content, &config)?;

            // 确定输出文件路径
            let output_path = match output {
                Some(custom_path) => custom_path,
                None => create_output_path(&path)?,
            };

            // 检查文件是否已存在，如果存在且未指定force，则返回错误
            if output_path.exists() && !force {
                return Err(anyhow!(
                    "输出文件 {} 已存在。使用 --force 选项覆盖现有文件。",
                    output_path.display()
                ));
            }

            // 写入处理后的内容到输出文件
            fs::write(&output_path, processed_content)
                .map_err(|e| anyhow!("无法写入文件 {}: {}", output_path.display(), e))?;

            println!("已加密文件并保存到: {}", output_path.display());
        }
        Commands::Decode {
            path,
            force,
            output,
        } => {
            // 读取文件内容
            let content = fs::read_to_string(&path)
                .map_err(|e| anyhow!("无法读取文件 {}: {}", path.display(), e))?;

            // 提示用户输入密码
            println!("请输入密码:");
            let mut password = String::new();
            std::io::stdin()
                .read_line(&mut password)
                .map_err(|e| anyhow!("读取密码失败: {}", e))?;
            let password = password.trim();

            // 处理文件内容，解密加密内容
            let processed_content = process_decode_file(&content, password)?;

            // 确定输出文件路径
            let output_path = match output {
                Some(custom_path) => custom_path,
                None => create_decoded_output_path(&path)?,
            };

            // 检查文件是否已存在，如果存在且未指定force，则返回错误
            if output_path.exists() && !force {
                return Err(anyhow!(
                    "输出文件 {} 已存在。使用 --force 选项覆盖现有文件。",
                    output_path.display()
                ));
            }

            // 写入处理后的内容到输出文件
            fs::write(&output_path, processed_content)
                .map_err(|e| anyhow!("无法写入文件 {}: {}", output_path.display(), e))?;

            println!("已解密文件并保存到: {}", output_path.display());
        }
    }

    Ok(())
}

/// 处理.cript文件内容，加密标签中的内容
fn process_cript_file(content: &str, config: &cript::config::CriptConfig) -> Result<String> {
    println!("processing {:?}", content);
    // 创建正则表达式匹配 {cript} 或 {cript=key-id} 格式的标签
    let re = Regex::new(r"(\{cript(?:=([^}]+))?\})((?s).*?)(\{\/cript\})").unwrap();

    // 使用替换功能，对每个匹配项进行处理
    let result = re.replace_all(content, |caps: &regex::Captures| {
        println!("{:?}", caps);
        // 获取开始标签
        let start_tag = &caps[1];
        // 获取结束标签
        let end_tag = &caps[4];
        // 获取密钥名称，如果没有指定则使用 "default"
        let key_name = caps.get(2).map_or("default", |m| m.as_str());

        // 获取需要加密的内容
        let plain_text = &caps[3];

        // 使用指定的密钥加密内容
        match encrypt_content(plain_text, key_name, config) {
            Ok(encrypted) => format!("{}{}{}", start_tag, encrypted, end_tag),
            Err(e) => {
                // 在实际应用中，你可能需要更好地处理错误
                // 这里简单地返回一个错误信息作为替换内容
                panic!("{{加密错误: {}}}", e)
            }
        }
    });

    Ok(result.to_string())
}

/// 使用指定的密钥加密内容
fn encrypt_content(
    content: &str,
    key_name: &str,
    config: &cript::config::CriptConfig,
) -> Result<String> {
    // 从配置中获取公钥
    let public_key = config.get_public_key(key_name).context("加载公钥失败")?;

    // 加密内容
    let mut csprng = rand::thread_rng();
    let encrypted_bytes = ecies_ed25519::encrypt(&public_key, content.as_bytes(), &mut csprng)
        .map_err(|e| anyhow!("加密失败: {}", e))?;

    // 将加密后的内容转换为Base64编码
    let encrypted_base64 = base64::prelude::BASE64_STANDARD.encode(&encrypted_bytes);

    Ok(encrypted_base64)
}
fn create_output_path(input_path: &Path) -> Result<PathBuf> {
    let file_name = input_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("无法获取文件名"))?;

    // 获取所有扩展名
    let extensions: Vec<_> = file_name.split('.').collect();

    if extensions.len() <= 1 {
        return Err(anyhow!("文件必须包含扩展名"));
    }

    let parent = input_path.parent().unwrap_or(Path::new(""));

    // 根据扩展名数量构建新文件名
    let new_filename = if extensions.len() > 2 {
        // 如果有多个扩展名，确保倒数第二个是 cript
        if extensions[extensions.len() - 2] != "cript" {
            return Err(anyhow!("文件必须包含.cript后缀"));
        }
        // 移除倒数第二个扩展名（cript）
        let mut parts = extensions.clone();
        parts.remove(parts.len() - 2);
        parts.join(".")
    } else {
        // 只有一个扩展名时，确保是 cript
        if extensions[1] != "cript" {
            return Err(anyhow!("文件必须是.cript后缀"));
        }
        // 只保留文件名部分
        extensions[0].to_string()
    };

    Ok(parent.join(new_filename))
}

/// 处理文件内容，解密加密内容
fn process_decode_file(content: &str, password: &str) -> Result<String> {
    // 创建正则表达式匹配 {cript} 或 {cript=key-id} 格式的标签及其内容
    let re = Regex::new(r"(\{cript(?:=([^}]+))?\})([^{]+)(\{\/cript\})").unwrap();

    // 使用替换功能，对每个匹配项进行处理
    let result = re.replace_all(content, |caps: &regex::Captures| {
        // 获取开始标签
        let start_tag = &caps[1];
        // 获取结束标签
        let end_tag = &caps[4];
        // 获取加密的内容（Base64编码）
        let encrypted_base64 = caps[3].trim();

        // 使用密码解密内容
        match decrypt_content(encrypted_base64, password) {
            Ok(decrypted) => format!("{}{}{}", start_tag, decrypted, end_tag),
            Err(e) => {
                // 在实际应用中，你可能需要更好地处理错误
                panic!("{}{}{}{}{}", start_tag, "[解密错误: ", e, "]", end_tag)
            }
        }
    });

    Ok(result.to_string())
}

/// 使用密码解密内容
fn decrypt_content(encrypted_base64: &str, password: &str) -> Result<String> {
    // 将Base64编码的内容解码为字节
    let encrypted_bytes = base64::prelude::BASE64_STANDARD
        .decode(encrypted_base64)
        .map_err(|e| anyhow!("Base64解码失败: {}", e))?;

    // 使用密码生成私钥
    let secret_key = cript::passwd_to_secret_key(password);

    // 解密内容
    let decrypted_bytes = ecies_ed25519::decrypt(&secret_key, &encrypted_bytes)
        .map_err(|e| anyhow!("解密失败: {}", e))?;

    // 将解密后的字节转换为字符串
    let decrypted_text =
        String::from_utf8(decrypted_bytes).map_err(|e| anyhow!("解码UTF-8失败: {}", e))?;

    Ok(decrypted_text)
}

/// 创建解密输出文件路径（添加.cript）
fn create_decoded_output_path(input_path: &Path) -> Result<PathBuf> {
    let file_stem = input_path
        .file_stem()
        .ok_or_else(|| anyhow!("无法获取文件名"))?;

    let parent = input_path.parent().unwrap_or(Path::new(""));
    let extension = input_path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");

    // 创建新的文件名：原文件名.cript.原扩展名
    let new_filename = if extension.is_empty() {
        format!("{}.cript", file_stem.to_string_lossy())
    } else {
        format!("{}.cript.{}", file_stem.to_string_lossy(), extension)
    };

    Ok(parent.join(new_filename))
}
