# chainpack-rpc-block Wireshark dissector
This is a Wireshark dissector for the block transport layer of SHV RPC as described [here](https://silicon-heaven.github.io/shv-doc/rpctransportlayer/stream.html#block).

## Dependencies
### cp2cp
_chainpack-rpc-block-dissector_ expects _cp2cp_ to be in your `PATH`. Alternatively, you can specify the location of _cp2cp_ via the `WIRESHARK_CP2CP_COMMAND` environmental variable (pass it to Wireshark).
_cp2cp_ can be installed in multiple ways.
#### `cargo install`
```
cargo install --git https://github.com/silicon-heaven/libshvproto-rs
```
Make sure the cargo installation prefix is in your `PATH`.

#### AUR
If you're using Arch Linux, you can use the AUR package: https://aur.archlinux.org/packages/cp2cp-git.

#### Download from libshvproto-rs CI
Visit [libshvproto-rs](https://github.com/silicon-heaven/libshvproto-rs) project [Actions](https://github.com/silicon-heaven/libshvproto-rs/actions).

#### Building manually
```
git clone https://github.com/silicon-heaven/libshvproto-rs
cd libshvproto-rs
cargo build
export WIRESHARK_CP2CP_COMMAND="$(pwd)/target/debug/cp2cp"
```

## Installation
### AUR
If you're using Arch Linux, there's an AUR package available [here](https://aur.archlinux.org/packages/wireshark-chainpack-rpc-block-dissector-git).
### Installing manually
Copy the dissector script into the Wireshark plugin directory as described [here](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).
