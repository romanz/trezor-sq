use std::ffi::OsString;
use std::io;
/// Use TREZOR for OpenPGP signatures.
use std::path::Path;

extern crate clap;
extern crate fern;
extern crate sequoia_openpgp as openpgp;
extern crate subprocess;
extern crate trezor;

#[macro_use]
extern crate log;

use openpgp::armor;
use openpgp::constants::{HashAlgorithm, PublicKeyAlgorithm};
use openpgp::crypto::{self, mpis};
use openpgp::packet::Key;
use openpgp::parse::Parse;
use openpgp::serialize::stream;
use openpgp::TPK;

fn handle_interaction<T, R: trezor::TrezorMessage>(
    resp: trezor::TrezorResponse<T, R>,
) -> Result<T, trezor::Error> {
    match resp {
        trezor::TrezorResponse::Ok(res) => Ok(res),
        trezor::TrezorResponse::Failure(_) => resp.ok(), // assering ok() returns the failure error
        trezor::TrezorResponse::ButtonRequest(req) => handle_interaction(req.ack()?),
        trezor::TrezorResponse::PinMatrixRequest(_req) => panic!("TREZOR is locked"),
        trezor::TrezorResponse::PassphraseRequest(_req) => panic!("TREZOR has passphrase"),
        trezor::TrezorResponse::PassphraseStateRequest(_req) => panic!("TREZOR has passphrase"),
    }
}

struct ExternalSigner {
    sigkey: Key,
    userid: String,
}

impl ExternalSigner {
    pub fn from_file(path: &Path, user_id: &str) -> openpgp::Result<Self> {
        let tpk = TPK::from_file(path)?;
        if tpk
            .userids()
            .find(|u| u.userid().value() == user_id.as_bytes())
            .is_none()
        {
            let msg = format!("{:?} has no user ID {}", path, user_id);
            return Err(openpgp::Error::UnsupportedTPK(msg).into());
        }
        let (_sig, _rev, key) = tpk
            .keys_valid()
            .signing_capable()
            .next()
            .expect("no valid signing key");
        let userid_str = String::from_utf8(
            tpk.userids()
                .next() // Primary user ID should be the first one.
                .expect("no user IDs")
                .userid()
                .value()
                .to_vec(),
        )?;
        Ok(ExternalSigner {
            sigkey: key.clone(),
            userid: userid_str,
        })
    }
}

impl crypto::Signer for ExternalSigner {
    /// Return static public key from file.
    fn public(&self) -> &Key {
        &self.sigkey
    }

    /// Creates a signature over the `digest` produced by `hash_algo`.
    fn sign(
        &mut self,
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> openpgp::Result<mpis::Signature> {
        match hash_algo {
            HashAlgorithm::SHA256 | HashAlgorithm::SHA512 => (),
            _ => return Err(openpgp::Error::UnsupportedHashAlgorithm(hash_algo).into()),
        }
        let mut digest = digest.to_vec();
        assert!(digest.len() >= 32);
        let curve = match self.sigkey.pk_algo() {
            PublicKeyAlgorithm::EdDSA => "ed25519",
            PublicKeyAlgorithm::ECDSA => {
                digest.split_off(32); // Keep only the first 256 bits.
                "nist256p1"
            }
            _ => {
                return Err(
                    openpgp::Error::UnsupportedPublicKeyAlgorithm(self.sigkey.pk_algo()).into(),
                )
            }
        };

        let mut identity = trezor::protos::IdentityType::new();
        identity.set_host(self.userid.to_owned());
        identity.set_proto("gpg".to_owned());

        let mut trezor = trezor::unique(false)?;
        trezor.init_device()?;
        let sig = handle_interaction(trezor.sign_identity(identity, digest, curve.to_owned())?)?;
        if sig.len() != 65 {
            return Err(openpgp::Error::BadSignature(format!(
                "invalid signature size: {}",
                sig.len()
            ))
            .into());
        }
        Ok(mpis::Signature::ECDSA {
            r: mpis::MPI::new(&sig[1..33]),
            s: mpis::MPI::new(&sig[33..]),
        })
    }
}

fn main() {
    let matches = clap::App::new("OpenPGP git wrapper for TREZOR")
        .arg(
            clap::Arg::with_name("userid")
                .short("u")
                .value_name("USERID")
                .help("User ID for signature")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("detached")
                .short("b")
                .help("Make a detached signature"),
        )
        .arg(
            clap::Arg::with_name("sign")
                .short("s")
                .help("Sign message from stdin"),
        )
        .arg(
            clap::Arg::with_name("verify")
                .long("verify")
                .takes_value(true)
                .help("Verify signature"),
        )
        .arg(
            clap::Arg::with_name("armor")
                .short("a")
                .help("Output armored signature"),
        )
        .arg(
            clap::Arg::with_name("status_fd")
                .long("status-fd")
                .takes_value(true)
                .help("File descriptor for status messages"),
        )
        .arg(
            clap::Arg::with_name("keyid_format")
                .long("keyid-format")
                .default_value("long")
                .takes_value(true)
                .help("TODO"),
        )
        .arg(clap::Arg::with_name("file").index(1).required(false))
        .get_matches();

    let home_dir: OsString = std::env::var_os("GNUPGHOME").expect("GNUPGHOME is not set");
    let pubkey_path = std::path::Path::new(&home_dir).join("trezor.asc");
    trace!("pubkey_path = {:?}", pubkey_path);

    if matches.is_present("sign") {
        let userid = matches.value_of("userid").expect("missing USERID");
        trace!("userid = {:?}", userid);

        assert!(matches.is_present("detached"));
        assert!(matches.is_present("armor"));
        assert_eq!(matches.value_of("status_fd").unwrap_or("2"), "2"); // stderr

        let mut signer =
            ExternalSigner::from_file(&pubkey_path, userid).expect("no ExternalSigner signer");
        let signers: Vec<&mut dyn crypto::Signer> = vec![&mut signer];

        let sink = armor::Writer::new(io::stdout(), armor::Kind::Signature, &[])
            .expect("Failed to create an armored writer.");

        let mut signer = stream::Signer::detached(stream::Message::new(sink), signers, None)
            .expect("Failed to create detached signer");

        io::copy(&mut io::stdin(), &mut signer).expect("Failed to sign data");

        signer.finalize().expect("Failed to write data");

        // https://github.com/git/git/blob/cd69ec8cde54af1817630331fc441f493866f0d4/gpg-interface.c#L318
        eprintln!("\n[GNUPG:] SIG_CREATED ");
        return;
    }
    if matches.is_present("verify") {
        assert_eq!(matches.value_of("status_fd").unwrap_or("1"), "1"); // stdout
        assert_eq!(matches.value_of("file").expect("missing input file"), "-"); // stdin
        let sigfile = matches.value_of("verify").expect("missing signature");

        let result = subprocess::Exec::cmd("/home/roman/Code/sequoia/target/debug/sqv")
            .arg("--keyring")
            .arg(&pubkey_path)
            .arg(sigfile)
            .arg("/dev/stdin") // input file (whose signature we are verifying)
            .capture()
            .expect("Popen failed");
        if result.success() {
            println!("\n[GNUPG:] GOODSIG ");
            eprint!("✓ ");
            std::process::exit(0);
        } else {
            println!("\n[GNUPG:] BADSIG ");
            eprint!("✗ ");
            std::process::exit(1);
        }
    }

    panic!("unsupported command: {:?}", matches);
}
