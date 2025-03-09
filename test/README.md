# Cript

A simple text file encrypt/decrypt cli tool.

## What does it do?

It uses ecies(curve25519 + aes-gcm) to encrypt/decrypt blocks of your text file.

For example, a `test.md` with following content:

```markdown
# Test

{cript}Hello Cript{/cript}

{cript}
Hello Cript
{/cript}

asdasdjsak
```

Can be convert into:

```markdown
# Test

{cript}Hello Cript{/cript}

{cript}
Hello Cript
{/cript}

asdasdjsak
```

And vice versa.

- **Cript Blocks**:
  There are two types of Cipt Blocks:
  - Plain Text: defined by `{cript[=<key-id>]}<plain-text-content>{/cript}` tags.
  - Encrypted: defined by `{cript[=<key-id>],<encrypted-content>/}` tags.
  The `<key-id>` specified which *Public Key* and *Password* to use/verify for encryption/decryption.
  If ignored, then it will be `default`.
- **Public key** and **Password**:
  ECIES uses a *public key* for *encryption* and a *secret key* for *decryption*.

  And they are parsed from the *password*.

  The *public keys* are configured in `Cript.toml` by `keys.<key-id> = <public_key>` as base64 encoded string, and the *passwords* are provided through evironment variables like `cript_<key-id>`.

## Install

```rust
cargo install --git https://github.com/AzurIce/cript.git --locked
```

## Usage

```toml
# Cript.toml
extensions = ["ext"] # leave empty for all ext
[key]
default = "<base64-public-key>"
a = "<base64-public-key>"
```

```shell
cript keys set <key-id> <password>
cript keys verify <key-id> <password>
cript keys rm <keyi-d>
cript keys list
cript encrypt <path> # process all files matches the extensions under the path
cript decrypt <path> # process all files matches the extensions under the path
```
