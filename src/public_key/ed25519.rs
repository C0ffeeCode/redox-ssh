use std::io::{self, Read, Write};
use std::io::ErrorKind::InvalidData;

use crypto::ed25519;
use rand::RngCore;

use crate::public_key::{
    CryptoSystem, KeyPair, KeyPairIdValidationError, SigningError
};

pub static ED25519: CryptoSystem = CryptoSystem {
    id: "ed25519",
    generate_key_pair: Ed25519KeyPair::generate,
    import: Ed25519KeyPair::import,
    read_public: Ed25519KeyPair::read_public,
};

struct Ed25519KeyPair {
    private: Option<[u8; 64]>,
    public: [u8; 32],
}

impl Ed25519KeyPair {
    fn generate(_: Option<u32>) -> Box<dyn KeyPair> {
        let mut seed = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut seed);

        let (private, public) = ed25519::keypair(&seed);
        Box::new(Ed25519KeyPair {
            private: Some(private),
            public,
        })
    }

    fn import(mut r: &mut dyn Read) -> io::Result<Box<dyn KeyPair>> {
        use crate::packet::ReadPacketExt;

        if r.read_utf8()? != "ssh-ed25519" {
            return Err(io::Error::new(InvalidData, "not a ED25519 key"));
        }

        if r.read_uint32()? != 32 {
            return Err(io::Error::new(InvalidData, "invalid ED25519 key"));
        }

        let mut public = [0u8; 32];
        r.read_exact(&mut public)?;

        if r.read_uint32()? != 64 {
            return Err(io::Error::new(InvalidData, "invalid ED25519 key"));
        }

        let mut private = [0u8; 64];
        r.read_exact(&mut private)?;

        Ok(Box::new(Ed25519KeyPair {
            public,
            private: Some(private),
        }))
    }

    fn read_public(mut r: &mut dyn Read) -> io::Result<Box<dyn KeyPair>> {
        use crate::packet::ReadPacketExt;

        if r.read_uint32()? != 32 {
            return Err(io::Error::new(InvalidData, "invalid ED25519 key"));
        }

        let mut public = [0u8; 32];
        r.read_exact(&mut public)?;

        Ok(Box::new(Ed25519KeyPair {
            private: None,
            public,
        }))
    }
}

impl KeyPair for Ed25519KeyPair {
    fn system(&self) -> &'static CryptoSystem {
        &ED25519
    }

    fn has_private(&self) -> bool {
        self.private.is_some()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, KeyPairIdValidationError> {
        use std::io::Cursor;
        use crate::packet::ReadPacketExt;

        const EXPECTED_ID: &[u8] = b"ssh-ed25519";

        let mut reader = Cursor::new(signature);
        let received_id = reader.read_string().unwrap_or_default();

        if received_id == EXPECTED_ID {
            if let Ok(sig) = reader.read_string() {
                return Ok(ed25519::verify(data, &self.public, sig.as_slice()));
            }
        }
        Err(KeyPairIdValidationError {received_id, expected_id: EXPECTED_ID })
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        use crate::packet::WritePacketExt;
        if let Some(private_key) = self.private {
            let mut result = Vec::new();
            let sig = ed25519::signature(data, &private_key);
            result.write_string("ssh-ed25519")?;
            result.write_bytes(&sig)?;
            Ok(result)
        }
        else {
            Err(SigningError::NoPrivateKey)
        }
    }

    fn write_public(&self, w: &mut dyn Write) -> io::Result<()> {
        use crate::packet::WritePacketExt;
        w.write_string("ssh-ed25519")?;
        w.write_bytes(&self.public)
    }

    fn export(&self, w: &mut dyn Write) -> io::Result<()> {
        use crate::packet::WritePacketExt;
        w.write_string("ssh-ed25519")?;
        w.write_bytes(&self.public)?;
        if let Some(private_key) = self.private {
            w.write_bytes(&private_key)?;
        }
        Ok(())
    }
}
