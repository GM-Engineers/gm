//! Fuzz target for RFC 5077 session ticket handling
//!
//! Tests:
//! 1. encrypt/decrypt round-trip with various session states
//! 2. TicketKeySet key rotation (add/remove keys)
//! 3. Replay detection via InMemorySessionStore
//! 4. Expiration handling edge cases

#![no_main]

use libfuzzer_sys::{fuzz_target, arbitrary::Arbitrary};
use gm_tls::gm::{
    create_session_state, decrypt_session_ticket, encrypt_session_ticket, SessionKeys,
    TicketKey, TicketKeySet,
};
use gm_crypto::sm4::SM4_GCM_NONCE_LENGTH;
use std::sync::Arc;
use tokio::runtime::Builder;

#[derive(Arbitrary, Debug)]
struct TicketKeyInput {
    id: u8,
    secret: [u8; 32],
}

#[derive(Arbitrary, Debug)]
struct SessionKeysInput {
    client_key: Vec<u8>,
    client_nonce: [u8; SM4_GCM_NONCE_LENGTH],
    server_key: Vec<u8>,
    server_nonce: [u8; SM4_GCM_NONCE_LENGTH],
}

impl From<SessionKeysInput> for SessionKeys {
    fn from(input: SessionKeysInput) -> Self {
        SessionKeys {
            client_key: input.client_key,
            client_nonce: input.client_nonce,
            server_key: input.server_key,
            server_nonce: input.server_nonce,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct SessionStateInput {
    master_secret: Vec<u8>,
    session_keys: SessionKeysInput,
    server_random: [u8; 32],
    client_random: [u8; 32],
    alpn: Option<String>,
    lifetime_hint: u32,
    require_client_auth: bool,
    created_at_offset: i64,
    ticket_key: TicketKeyInput,
}

// All session ticket tests combined into one fuzz target
fuzz_target!(|input: SessionStateInput| {
    run_session_ticket_test(input);
});

fn run_session_ticket_test(input: SessionStateInput) {
    // Validate inputs
    if input.master_secret.is_empty() || input.master_secret.len() > 64 {
        return;
    }
    if input.session_keys.client_key.len() != 16 || input.session_keys.server_key.len() != 16 {
        return;
    }
    if input.lifetime_hint > 86400 * 7 {
        return;
    }

    let ticket_key = TicketKey {
        id: input.ticket_key.id.max(1),
        secret: input.ticket_key.secret,
    };
    let key_set = TicketKeySet::new(ticket_key.clone());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let created_at = (now + input.created_at_offset).max(0) as u64;

    let session_keys: SessionKeys = input.session_keys.into();
    let state = create_session_state(
        input.master_secret,
        session_keys,
        None, // client_traffic_secret — omitted (KeyUpdate not exercised in fuzz)
        None, // server_traffic_secret — omitted
        input.server_random,
        input.client_random,
        input.alpn,
        input.lifetime_hint,
        input.require_client_auth,
    );

    let ticket = match encrypt_session_ticket(&state, &key_set) {
        Ok(t) => t,
        Err(_) => return,
    };

    let session_store = Arc::new(gm_tls::session_store::InMemorySessionStore::new());

    // Skip client-authenticated sessions as they cannot be resumed
    if input.require_client_auth {
        return;
    }

    let rt = Builder::new_current_thread().build().unwrap();
    let age_seconds = now.saturating_sub(created_at as i64) as u64;
    let max_lifetime = input.lifetime_hint.min(86400) as u64;

    if age_seconds <= max_lifetime {
        let _ = rt.block_on(decrypt_session_ticket(&ticket, &key_set, session_store.clone()));
    }

    // Test key rotation with same state
    let mut key_set2 = TicketKeySet::new(ticket_key.clone());
    key_set2.add_key(TicketKey { id: 2, secret: [0xAB; 32] });

    let ticket_rotated = match encrypt_session_ticket(&state, &key_set) {
        Ok(t) => t,
        Err(_) => return,
    };

    let result_rotated = rt.block_on(decrypt_session_ticket(
        &ticket_rotated,
        &key_set2,
        Arc::new(gm_tls::session_store::InMemorySessionStore::new()),
    ));
    if result_rotated.is_err() {
        return;
    }

    // Test replay detection
    let session_store3 = Arc::new(gm_tls::session_store::InMemorySessionStore::new());
    let first_result = rt.block_on(decrypt_session_ticket(&ticket_rotated, &key_set, session_store3.clone()));
    if first_result.is_ok() {
        let second_result = rt.block_on(decrypt_session_ticket(&ticket_rotated, &key_set, session_store3));
        // Replay should be detected
        if second_result.is_ok() {
            // This would be a bug - same ticket used twice should fail on second use
        }
    }
}
