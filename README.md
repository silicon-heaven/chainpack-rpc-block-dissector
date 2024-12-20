# chainpack-rpc-block Wireshark dissector
This is a Wireshark dissector for the block transport layer of SHV RPC as described [here](https://silicon-heaven.github.io/shv-doc/rpctransportlayer/stream.html#block).

## Dependencies
### cp2cp
- clone https://github.com/silicon-heaven/libshvproto-rs and install manually via `cargo install` or by using `cargo build` and copying the binary to your `PATH`.
- [AUR](https://aur.archlinux.org/packages/cp2cp-git) if you're on Arch

_chainpack-rpc-block-dissector_ expects _cp2cp_ to be in your `PATH`. Alternatively, you can specify the location of _cp2cp_ via the `WIRESHARK_CP2CP_COMMAND` environmental variable (pass it to Wireshark).

## Installation
### Installing manually
Copy the dissector script into the Wireshark plugin directory as described [here](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).
### AUR
If you're using Arch Linux, there's an AUR package available [here](https://aur.archlinux.org/packages/wireshark-chainpack-rpc-block-dissector-git).
