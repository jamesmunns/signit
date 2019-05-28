use dirs::home_dir;
use thrussh_keys::{
    load_secret_key,
    load_public_key,
    parse_public_key_base64,
    signature::Signature,
    key::{KeyPair, PublicKey},
};
use base64::{encode, decode};
use structopt::StructOpt;
use std::path::PathBuf;
use std::fs::read_to_string;
use serde_json;
use serde::{Serialize, Deserialize};
use reqwest;

#[derive(Debug, Serialize, Deserialize)]
struct SignIt {
    message: String,
    signature: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    github_user: Option<String>,
}

#[derive(StructOpt)]
enum Commands {
    /// Sign a message using an ed25519 private key
    #[structopt(name = "sign")]
    Sign {
        /// File to sign, defaults to stdin if no file is specified or -m is not used
        #[structopt(short = "i", parse(from_os_str))]
        input: Option<PathBuf>,

        /// Output of signature, defaults to stdout if no file is specified
        #[structopt(short = "o", parse(from_os_str))]
        output: Option<PathBuf>,

        /// Message to sign (overrides -i flag or stdin)
        #[structopt(short = "m")]
        message: Option<String>,

        /// Path to ed25519 private key, defaults to "$HOME/.ssh/id_ed25519"
        #[structopt(short = "k", parse(from_os_str))]
        private_key: Option<PathBuf>,

        /// Github username to couple with json output
        #[structopt(short = "g")]
        github: Option<String>,

        /// Pretty Print the JSON output
        #[structopt(short = "p")]
        pretty: bool,
    },

    /// Verify a message using an ed25519 public key
    #[structopt(name = "verify")]
    Verify {
        /// File to sign, defaults to stdin if no file is specified or -m is not used
        #[structopt(short = "i", parse(from_os_str))]
        input: Option<PathBuf>,

        /// Message to verify (overrides -i flag or stdin)
        #[structopt(short = "m")]
        message: Option<String>,

        /// Path to ed25519 public key, defaults to "$HOME/.ssh/id_ed25519.pub", overrides -g
        #[structopt(short = "k", parse(from_os_str))]
        public_key: Option<PathBuf>,

        /// Pull public keys from github
        #[structopt(short = "g")]
        github: bool,
    }
}

fn main() {
    let opt = Commands::from_args();

    match opt {
        Commands::Sign { input, output, message, private_key, github, pretty } => {

            let secret = get_private_key(private_key);
            let message = get_message(message, &input);

            let sig = secret.sign_detached(message.as_bytes()).unwrap();
            let sig = match sig {
                Signature::Ed25519(sig) => sig,
                _ => eject("Specified or detected key was not an Ed25519 key!"),
            };


            let out = SignIt {
                message,
                signature: encode(&sig.0[..]),
                github_user: github,
            };

            let outstr = if pretty {
                serde_json::to_string_pretty
            } else {
                serde_json::to_string
            }(&out).unwrap();

            write_or_print(output, outstr);

        },
        Commands::Verify { input, message, public_key, github } => {
            let msg = get_sig_message(message, &input);
            let guser = match (github, &msg.github_user) {
                (true, Some(_)) => &msg.github_user,
                (true, None) => eject("No github user in message!"),
                (false, _) => &None,
            };
            let keys = get_public_keys(public_key, guser);

            let sig = decode(&msg.signature)
                .unwrap_or_else(|_e| eject("Signature not proper base64!") );

            let good = keys
                .iter()
                .any(|k| {
                    k.verify_detached(msg.message.as_bytes(), &sig)
                });

            if !good {
                eject("Verification failed!")
            } else {
                println!("Verified!");
            }
        }
    }
}

fn write_or_print(output: Option<PathBuf>, outstr: String) {
    use std::io::Write;
    if let Some(opath) = output {
        let mut file = std::fs::File::create(&opath)
            .unwrap_or_else(|e| {
                eject(&format!("Failed to open file: {:?}\nError: {:?}", opath, e));
            });
        file.write_all(outstr.as_bytes())
            .unwrap_or_else(|e| {
                eject(&format!("Failed to write to file: {:?}\nError: {:?}", opath, e));
            });
    } else {
        println!("{}", outstr);
    }
}

fn get_sig_message(message: Option<String>, input: &Option<PathBuf>) -> SignIt {
    let raw = get_message(message, input);
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| {
            eject(&format!("Failed to parse message: {:?}\nError: {:?}", raw, e))
        })
}

fn get_message(message: Option<String>, input: &Option<PathBuf>) -> String {
    if let Some(msg) = message {
        return msg;
    }

    if let Some(fpath) = input {
        return read_to_string(&fpath)
            .unwrap_or_else(|e| {
                eject(&format!("Failed to read file {:?}\nError: {:?}", fpath, e));
            });
    }

    use std::io::Read;
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)
        .unwrap_or_else(|e| {
            eject(&format!("Failed to read stdin\nError: {:?}", e))
        });
    buffer
}

fn get_private_key(path: Option<PathBuf>) -> KeyPair {
    let path = path
        .unwrap_or_else(|| {
            let mut private_key_file = home_dir()
                .unwrap_or_else(|| {
                    eject("No home directory detected, please specify private key using -k!");
                });
            private_key_file.push(".ssh");
            private_key_file.push("id_ed25519");

            private_key_file
        });

    load_secret_key(&path, None)
        .unwrap_or_else(|e| {
            eject(&format!("Unable to detect private key, please specify using -k!\nError: {:?}", e));
        })
}

fn get_public_keys(path: Option<PathBuf>, guser: &Option<String>) -> Vec<PublicKey> {
    let mut ed_keys = vec![];

    if let Some(pkpath) = path {
        let key = load_public_key(&pkpath)
            .unwrap_or_else(|e| {
                eject(&format!("Failed to load key at {:?}\nError: {:?}", pkpath, e));
            });
        ed_keys.push(key);
    } else if let Some(user) = guser {
        let url = format!("https://github.com/{}.keys", user);
        let body = reqwest::get(&url)
            .unwrap_or_else(|e| {
                eject(&format!("Failed to get github keys!\nError: {:?}", e))
            })
            .text()
            .unwrap_or_else(|e| {
                eject(&format!("Failed to get github keys!\nError: {:?}", e))
            });

        body.lines()
            .filter(|l| {
                l.starts_with("ssh-ed25519")
            })
            .filter_map(|l| l.split_whitespace().skip(1).next())
            .filter_map(|l| {
                parse_public_key_base64(l).ok()
            })
            .for_each(|pk| ed_keys.push(pk));
    }

    ed_keys
}

pub fn eject(reason: &str) -> ! {
    eprintln!("{}", reason);
    std::process::exit(-1);
}
