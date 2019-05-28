# `signit`

A tool to help you sign and verify signatures of messages using your ed25519 ssh keys.

If you add your ed25519 public key to your github account, anyone can verify your messages without giving them your public key manually!

## Prerequisite: Generating an ed25519 SSH Key

Run the following command, and follow the instructions. You don't need to do this if you already have an ed25519 ssh key.

```
ssh-keygen -t ed25519
```

## Round Trip Example

This uses my `$HOME/.ssh/id_ed25519` key to sign, and my public keys [on github](https://github.com/jamesmunns.keys) to verify.

```
signit sign -p -m "Hello, world" -g jamesmunns | tee msg.json | signit verify -g && cat ./msg.json

Verified!
{
  "message": "Hello, world",
  "signature": "JruolFnpOE6uQy0gqSE2VfrHPYr2De7cDdiIOAhDLIkIN5MmK+oT4HRNpB2Y0QSY1XGVMODHG1fWOeFwdl+YDg==",
  "github_user": "jamesmunns"
}
```

## Signing Messages

```
signit sign --help

signit-sign 0.1.0
James Munns <james.munns@ferrous-systems.com>
Sign a message using an ed25519 private key

USAGE:
    signit sign [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -p               Pretty Print the JSON output
    -V, --version    Prints version information

OPTIONS:
    -g <github>             Github username to couple with json output
    -i <input>              File to sign, defaults to stdin if no file is specified or -m is not used
    -m <message>            Message to sign (overrides -i flag or stdin)
    -o <output>             Output of signature, defaults to stdout if no file is specified
    -k <private_key>        Path to ed25519 private key, defaults to "$HOME/.ssh/id_ed25519"
```

## Verifying Messages

```
signit verify --help

signit-verify 0.1.0
James Munns <james.munns@ferrous-systems.com>
Verify a message using an ed25519 public key

USAGE:
    signit verify [FLAGS] [OPTIONS]

FLAGS:
    -g               Pull public keys from github
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i <input>             File to sign, defaults to stdin if no file is specified or -m is not used
    -m <message>           Message to verify (overrides -i flag or stdin)
    -k <public_key>        Path to ed25519 public key, defaults to "$HOME/.ssh/id_ed25519.pub", overrides -g
```



## Installation

```
cargo install signit
```

## Upgrade

```
cargo install -f signit
```

## License

This project is licensed under the terms of both the [MIT License] and the [Apache License v2.0]

Copies of the licenses used by this project may also be found here:

* [MIT License Hosted]
* [Apache License v2.0 Hosted]

[MIT License]: ./LICENSE-MIT
[Apache License v2.0]: ./LICENSE-APACHE
[MIT License Hosted]: https://opensource.org/licenses/MIT
[Apache License v2.0 Hosted]: http://www.apache.org/licenses/LICENSE-2.0

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.
