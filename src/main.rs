/// Use TREZOR for ECDSA OpenPGP signatures.
use std::env;
use std::io;

extern crate sequoia_openpgp as openpgp;
extern crate trezor;

use openpgp::armor;
use openpgp::constants::DataFormat;
use openpgp::constants::HashAlgorithm;
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
    pub fn from_file(path: &str) -> openpgp::Result<Self> {
        let tpk = TPK::from_file(path)?;
        let (_sig, _rev, key) = tpk
            .keys_valid()
            .signing_capable()
            .next()
            .expect("no valid signing key");

        let userid = match tpk.userids().next() {
            Some(userid) => userid.userid(),
            None => {
                return Err(
                    openpgp::Error::InvalidArgument(format!("{} has no user ID", path)).into(),
                )
            }
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
    fn sign(
        &mut self,
        _hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> openpgp::Result<mpis::Signature> {
        let mut trezor = trezor::unique(false)?;
        trezor.init_device()?;
        let mut identity = trezor::protos::IdentityType::new();
        identity.set_host(self.userid.to_owned());
        identity.set_proto("gpg".to_owned());
        let sig = handle_interaction(trezor.sign_identity(
            identity,
            digest[..32].to_owned(),
            "nist256p1".to_owned(),
        )?)?;
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
