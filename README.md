```
cript list
cript encode <source.cript[.xxx]>[ --force][ -o <encoded[.xxx]>]
cript decode <encoded[.xxx]>[ --force][ -o <source.cript[.xxx]>]
cript gen-public-key <passwd>
```

```toml
# Cript.toml
[key]
default = "<base64-public-key>"
a = "<base64-public-key>"
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