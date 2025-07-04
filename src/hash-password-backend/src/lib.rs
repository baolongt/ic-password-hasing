use std::cell::RefCell;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::time::Duration;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use bcrypt::{hash as bcrypt_hash, verify as bcrypt_verify, DEFAULT_COST};
use ic_cdk::{query, update, init, post_upgrade};
use getrandom::register_custom_getrandom;

// Store the Argon2 hash string (which already embeds the salt) in thread-local storage.
thread_local! {
    static PASSWORD_HASH: RefCell<Option<String>> = RefCell::new(None);
    static BCRYPT_HASH: RefCell<Option<String>> = RefCell::new(None);
    static RNG: RefCell<Option<StdRng>> = RefCell::new(None);
}

#[init]
fn init() {
    init_rng();
}

#[post_upgrade]
fn post_upgrade() {
    init_rng();
}

/// Initialize the on-chain RNG with secure randomness from `raw_rand`.
fn init_rng() {
    // We cannot call `raw_rand` directly inside a lifecycle function, so we schedule
    // a zero-delay timer that performs the async call right after initialization.
    ic_cdk_timers::set_timer(Duration::ZERO, || ic_cdk::spawn(async {
        match ic_cdk::api::management_canister::main::raw_rand().await {
            Ok((seed_vec,)) => {
                let mut seed = [0u8; 32];
                let copy_len = seed_vec.len().min(32);
                seed[..copy_len].copy_from_slice(&seed_vec[..copy_len]);
                RNG.with(|rng| *rng.borrow_mut() = Some(StdRng::from_seed(seed)));
            }
            Err(e) => ic_cdk::api::print(format!("raw_rand failed: {:?}", e)),
        }
    }));
}

/// Custom implementation for the `getrandom` crate pointing to our thread-local RNG.
fn custom_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    RNG.with(|rng| {
        if let Some(rng) = rng.borrow_mut().as_mut() {
            rng.fill_bytes(buf);
            Ok(())
        } else {
            Err(getrandom::Error::UNSUPPORTED)
        }
    })
}

// Make this implementation available to all dependent crates that rely on `getrandom`.
register_custom_getrandom!(custom_getrandom);

/// Set (or replace) the canister password.
/// Internally we hash the supplied password with Argon2 using a salt that is
/// derived from the current IC time, then persist the resulting hash string in
/// thread-local storage.
#[update]
fn set_password(password: String) -> Result<(), String> {
    // Derive a 16-byte salt from the current IC time. This keeps dependencies
    // minimal while still ensuring different salts on subsequent calls.
    let nanos_since_epoch = ic_cdk::api::time();
    let salt_bytes = nanos_since_epoch.to_be_bytes();
    let salt_hex = hex::encode(salt_bytes);
    let salt = SaltString::new(&salt_hex).map_err(|e| format!("invalid salt: {e:?}"))?;

    // Hash the password.
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("failed to hash password: {e:?}"))?
        .to_string();

    // Persist the hash so it can be verified later.
    PASSWORD_HASH.with(|cell| {
        *cell.borrow_mut() = Some(hash);
    });

    Ok(())
}

/// Verify the supplied password against the previously stored hash.
#[query]
fn check_password(password: String) -> bool {
    PASSWORD_HASH.with(|cell| {
        if let Some(stored_hash) = &*cell.borrow() {
            // Parse the stored hash
            if let Ok(parsed_hash) = PasswordHash::new(stored_hash) {
                return Argon2::default()
                    .verify_password(password.as_bytes(), &parsed_hash)
                    .is_ok();
            }
        }
        false
    })
}

/// Retrieve the currently stored Argon2 hash string (if any).
#[query]
fn get_password_hash() -> Option<String> {
    PASSWORD_HASH.with(|cell| cell.borrow().clone())
}

/// Set (or replace) the canister password using BCrypt.
#[update]
fn set_password_bcrypt(password: String) -> Result<(), String> {
    let hash = bcrypt_hash(password, DEFAULT_COST).map_err(|e| format!("bcrypt error: {e:?}"))?;
    BCRYPT_HASH.with(|cell| {
        *cell.borrow_mut() = Some(hash);
    });
    Ok(())
}

/// Verify the supplied password against the BCrypt hash.
#[query]
fn check_password_bcrypt(password: String) -> bool {
    BCRYPT_HASH.with(|cell| {
        if let Some(stored_hash) = &*cell.borrow() {
            bcrypt_verify(password, stored_hash).unwrap_or(false)
        } else {
            false
        }
    })
}

/// Retrieve the currently stored BCrypt hash (if any).
#[query]
fn get_password_hash_bcrypt() -> Option<String> {
    BCRYPT_HASH.with(|cell| cell.borrow().clone())
}



// Export the candid interface so the .did file can be generated automatically.
ic_cdk::export_candid!();
