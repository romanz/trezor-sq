/// Use TREZOR for ed25519 signatures.
use std::env;
use std::io;

extern crate sequoia_openpgp as openpgp;
extern crate subprocess;

use openpgp::armor;
use openpgp::constants::DataFormat;
use openpgp::constants::HashAlgorithm;
use openpgp::crypto::{self, mpis};
use openpgp::packet::Key;
use openpgp::parse::Parse;
use openpgp::serialize::stream;
use openpgp::TPK;
use openpgp::{Error, Result};

struct ExternalSigner {
    sigkey: Key,
    userid: String,
}

impl ExternalSigner {
    pub fn from_file(path: &str) -> Result<Self> {
        let tpk = TPK::from_file(path)?;
        let (_sig, _rev, key) = tpk
            .keys_valid()
            .signing_capable()
            .next()
            .expect("no valid signing key");

        let userid = match tpk.userids().next() {
            Some(userid) => userid.userid(),
            None => return Err(Error::InvalidArgument(format!("{} has no user ID", path)).into()),
        };
        let userid = match String::from_utf8(userid.value().to_vec()) {
            Ok(value) => value,
            Err(err) => return Err(err.into()),
        };
        Ok(ExternalSigner {
            sigkey: key.clone(),
            userid,
        })
    }
}

impl crypto::Signer for ExternalSigner {
    /// Return static public key from file.
    fn public(&self) -> &Key {
        &self.sigkey
    }

    /// Creates a signature over the `digest` produced by `hash_algo`.
    fn sign(&mut self, _hash_algo: HashAlgorithm, digest: &[u8]) -> Result<mpis::Signature> {
        use subprocess::{Exec, Redirection};
        let mut p = Exec::cmd("./src/trezor-gpg-sign.py")
            .arg(&self.userid)
            .stdin(Redirection::Pipe)
            .stdout(Redirection::Pipe)
            .popen()?;

        let (out, _err) = p.communicate_bytes(Some(digest))?;
        let sig = out.expect("no stdout");
        if sig.len() != 64 {
            return Err(
                Error::BadSignature(format!("invalid signature size: {}", sig.len())).into(),
            );
        }
        Ok(mpis::Signature::EdDSA {
            r: mpis::MPI::new(&sig[..32]),
            s: mpis::MPI::new(&sig[32..]),
        })
    }
}

fn main() {
    let pubkey_path = env::args()
        .skip(1)
        .next()
        .expect("missing pubkey file path");
    let mut signer = ExternalSigner::from_file(&pubkey_path).expect("no ExternalSigner signer");
    let signers: Vec<&mut dyn crypto::Signer> = vec![&mut signer];

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.  First, we want the output to be
    // ASCII armored.
    let sink = armor::Writer::new(io::stdout(), armor::Kind::Message, &[])
        .expect("Failed to create an armored writer.");

    // Now, create a signer that emits a signature.
    let signer = stream::Signer::new(stream::Message::new(sink), signers, None)
        .expect("Failed to create signer");

    // Then, create a literal writer to wrap the data in a literal
    // message packet.
    let mut literal = stream::LiteralWriter::new(signer, DataFormat::Binary, None, None)
        .expect("Failed to create literal writer");

    // Copy all the data.
    io::copy(&mut io::stdin(), &mut literal).expect("Failed to sign data");

    // Finally, teardown the stack to ensure all the data is written.
    literal.finalize().expect("Failed to write data");
}
