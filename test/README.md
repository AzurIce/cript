# Cript

A simple text file encrypt/decrypt cli tool.

## What does it do?

It uses ecies(curve25519 + aes-gcm) to encrypt/decrypt blocks of your text file.

For example, a `test.md` with following content:

```markdown
# Test

{cript,v00Xwj4kitXTUEoL86rzCqWzzNkPJjWtGNkbl1BeARt4Rlr+gDPw7Tdoqj1OaN31FtLhsX5PiQRZDJ7mlPIHVHyhr+fPvJ0=/}

{cript,FVVOj6lj9w/VDFJwR3wRqNha2sMIwe4T02QYZWcPC0zQPuv17HhjiTUIF3INWeJ3HxZAAjC/GRH4oofa7tEI4L5fFpzLgSVO5Q==/}

asdasdjsak
```

Can be convert into:

```markdown
# Test

{cript,cUwu5okuevzpksLHD5M6u1y4OVBTjXd9SZiD8xwjiKLluZqz0zwnoVf8AuA27rAlwjHJUNQBtNGtKQrbJ+LZrI/MtzVOj5E=/}

{cript,oHQJ1RE1GYxKiu31L1mpeV6RxHHydvSpTenqsuLGaVm5tzCNrzteGhE0RJUnyuwwNsevYRsBX9QtZJmUq4PJOK8jcoV8ws+bYw==/}

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
