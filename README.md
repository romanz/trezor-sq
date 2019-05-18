# Warning

This tool is still in **EXPERIMENTAL** mode, so please note that the API and features may change without backwards compatibility!

# Usage

Initialize your OpenPGP identity using the instructions [here](https://github.com/romanz/trezor-agent/blob/master/doc/README-GPG.md).
```bash
$ trezor-gpg init -e ed25519 --homedir /tmp/g foo@bar
$ export GNUPGHOME='/tmp/g'
```

Sign messages using the following command:
```bash
$ echo "message to be signed" | cargo run -- ${GNUPGHOME}/pubkey.asc | gpg --verify
    Finished dev [unoptimized + debuginfo] target(s) in 0.11s
     Running `target/debug/trezor-sq /tmp/g/pubkey.asc`
Please confirm action on your Trezor device
gpg: Signature made Sun 19 May 2019 21:11:23 IDT
gpg:                using EDDSA key EAC76B0BF8719523D9781AA73A7231DE0C9C7B97
gpg: Good signature from "foo@bar" [ultimate]
```
