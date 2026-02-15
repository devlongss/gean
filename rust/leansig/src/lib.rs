use leansig::signature::SignatureScheme;
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use rand::{SeedableRng,rngs::StdRng};

pub type LeanSignatureScheme = SIGTopLevelTargetSumLifetime32Dim64Base8;
pub type LeanPublicKey = <LeanSignatureScheme as SignatureScheme>::PublicKey;
pub type LeanSecretKey = <LeanSignatureScheme as SignatureScheme>::SecretKey;

#[repr(C)]
pub struct SecretKey {
    pub inner: LeanSecretKey,
}

#[repr(C)]
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
/// - `ptr` must be a valid pointer to `len` bytes.
/// - Caller is responsible for freeing returned memory.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_generate(
    seed: u64,
    activation_epoch: usize,
    num_active_epochs: usize,
) -> *mut Keypair {
    let mut rng = StdRng::seed_from_u64(seed);
    
    let (pk, sk) = <LeanSignatureScheme as SignatureScheme>::key_gen(&mut rng, activation_epoch, num_active_epochs);
    
    let public_key = PublicKey::new(pk);
    let secret_key = SecretKey::new(sk);
    
    let keypair = Box::new(Keypair {
        public_key,
        secret_key,
    });
    
    Box::into_raw(keypair)
}
