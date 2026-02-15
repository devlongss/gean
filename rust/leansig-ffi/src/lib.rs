use leansig::signature::SignatureScheme;
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use rand::{SeedableRng,rngs::StdRng};
use std::ptr;
use std::slice;
use ssz::Decode;

pub type LeanSignatureScheme = SIGTopLevelTargetSumLifetime32Dim64Base8;
pub type LeanPublicKey = <LeanSignatureScheme as SignatureScheme>::PublicKey;
pub type LeanSecretKey = <LeanSignatureScheme as SignatureScheme>::SecretKey;

pub struct SecretKey {
    pub inner: LeanSecretKey,
}

pub struct PublicKey {
    pub inner: LeanPublicKey,
}

pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl PublicKey {
    pub fn new(inner: LeanPublicKey) -> Self {
        Self { inner }
    }
}

impl SecretKey {
    pub fn new(inner: LeanSecretKey) -> Self {
        Self { inner }
    }
}

/// FFI: Exposed for Go (cgo) interoperability.
///
/// # Safety
/// - returned `ptr` must be a valid pointer to Keypair.
/// - Caller is responsible for freeing returned memory.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_generate(
    seed: u64,
    activation_epoch: usize,
    num_active_epochs: usize,
) -> *mut Keypair {
    let mut rng = StdRng::seed_from_u64(seed);

    let (pk, sk) = <LeanSignatureScheme as SignatureScheme>::key_gen(
        &mut rng,
        activation_epoch,
        num_active_epochs,
    );

    let public_key = PublicKey::new(pk);
    let secret_key = SecretKey::new(sk);

    let keypair = Box::new(Keypair {
        public_key,
        secret_key,
    });

    Box::into_raw(keypair)
}

// Get a pointer to the public key from a keypair
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_get_public_key(
    keypair: *const Keypair,
) -> *const PublicKey {
    if keypair.is_null() {
        return ptr::null();
    }

    unsafe { &(*keypair).public_key }
}

// Get a pointer to the secret key from a keypair
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_get_private_key(
    keypair: *const Keypair,
) -> *const SecretKey {
    if keypair.is_null() {
        return ptr::null();
    }

    unsafe { &(*keypair).secret_key }
}

/// FFI: Frees a heap-allocated XMSS `Keypair`.
///
/// # Safety
/// - `key_pair` must be a pointer previously returned by
///   `leansig_generate_keypair` (or any function that allocates a `Keypair` on the heap).
/// - Passing a null pointer is safe (function does nothing).
/// - After calling this function, the pointer must not be used again.
/// - Must only be called once per allocated `Keypair` to avoid double-free.
///
/// # Notes
/// - This function is intended for use from Go or other languages via FFI.
/// - It converts the raw pointer back into a `Box` and drops it, freeing the memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_free(key_pair: *mut Keypair) {
    if !key_pair.is_null() {
        unsafe {
            let _ = Box::from_raw(key_pair);
        }
    }
}

// Reconstruct a key pair from SSZ-encoded secret key and public key
// Returns a pointer to the KeyPair or null pointer on error
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_from_ssz_bytes(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    public_key_ptr: *const u8,
    public_key_len: usize,
) -> *mut Keypair {
    if secret_key_ptr.is_null() || public_key_ptr.is_null() {
        return ptr::null_mut()
    }
    
    unsafe  {
        let sk_slice = slice::from_raw_parts(secret_key_ptr, secret_key_len);
        let pk_slice = slice::from_raw_parts(public_key_ptr, public_key_len);
        
        let pk: LeanPublicKey = match LeanPublicKey::from_ssz_bytes(pk_slice) {
            Ok(key) => key,
            Err(_) => return ptr::null_mut(),
        };
        
        
        let sk: LeanSecretKey = match LeanSecretKey::from_ssz_bytes(sk_slice) {
            Ok(key) => key,
            Err(_) => return ptr::null_mut(),
        };
        
        let keypair = Box::new(Keypair {
            public_key: PublicKey::new(pk),
            secret_key: SecretKey::new(sk)
        });
        
        Box::into_raw(keypair)
    }
}
