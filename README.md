# Cript

A simple text encrypt/decrypt tool:
- `file.cript.md` <-> `file.md`
- `file.cript` <-> `file`
- ...

## What does it do?

It uses ecies(curve25519 + aes-gcm) to encrypt/decrypt blocks of your text file.

For example, a `test.cript.md` with following content:

```markdown
# Test

{cript}Hello Cript{/cript}

{cript=default}
Hello Cript
{/cript}

asdasdjsak
```

Can be convert to a `test.md` with following content and vice versa:

```markdown
# Test

{cript}p7nz62LXnIEdnAaYdaSD6wn3QNBanOylD2tmhdbDSOcl6Cg7xp/+Nx5SGAcaWk3eTx0xWXgUFKuyoMTPG0UvzaiW88QYZkY={/cript}

{cript=default}HZLLPbL+iBK2MJ0DadCg9Wn8cOcBD37VevQBs/PQbaGsRLykggzH4nZ3olBarxLonYDtZUfyTKjFAF52wqRlo3CIsOknlD4wCQ=={/cript}

asdasdjsak
```

- **Cript File**:
  The file has the name like `file.cript.xx` or `file.cript`.
  They can be converted between plain text and encrypted text by cript:
    - `file.cript.md` <-> `file.md`
    - `file.cript` <-> `file`
    - ...
- **Cript Block**:
  A block defined by `{cript[=<key-id>]}` and `{/cript}` tags.
  The Encrypting process will use the corresponding **Public Key** defined in `Cript.toml` in base64 string format.
  The decrypting process will use the corresponding **Password** provided through `cript_<key-id>=<password>` environment variables.
- **Public Key** and **Password**
  A Password can be parsed to a public key and the corresponding private key.
  The public key will be used to encrypt the blocks, and the private key will be used to decrypt the blocks.
  "Why not use the private key directly?"
  Because it is too hard to memorize

## Install

```rust
cargo install --git https://github.com/AzurIce/cript.git --locked
```

## Usage

```toml
# Cript.toml
[key]
default = "<base64-public-key>"
a = "<base64-public-key>"
```

```shell
cript keys set <key-id> <password>
cript keys verify <key-id> <password>
cript keys rm <keyi-d>
cript keys list
cript encrypt <path>
cript decrypt <path>
```

```
// source.cript[.xxx]

{cript}
multi
line
default
{/cript}

{cript=a}inline a{/cript}
```