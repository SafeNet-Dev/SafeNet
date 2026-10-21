use aes_gcm::{
    aead::{Aead, AeadCore, Generate, Key, KeyInit},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::consts::U12;

pub fn create_key() -> Key<Aes256Gcm> {
    Key::<Aes256Gcm>::generate()
}

pub fn encrypt(key: &Key<Aes256Gcm>, plaintext: &[u8]) -> Result<(Vec<u8>, Nonce<U12>), aes_gcm::Error> {
    // TODO: maing sure that every nonce is truly unique
    let nonce = Nonce::generate();
    let cipher = Aes256Gcm::new(key);

    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;

    Ok((ciphertext, nonce))
}

pub fn decrypt(key: &Key<Aes256Gcm>, ciphertext: &[u8], nonce: Nonce<U12>) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref());

    Ok(plaintext?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let plaintext = b"Hello, world!";
        let key = create_key();
        let Ok((ciphertext, nonce)) = encrypt(&key, plaintext) else {
            panic!("Encryption failed");
        };
        let decrypted_plaintext = decrypt(&key, &ciphertext, nonce).unwrap();
        assert_eq!(decrypted_plaintext, plaintext);
    }
}
