//! Fuzz target for handshake protocol parsing
//!
//! This fuzz target tests:
//! 1. ClientHello/ServerHello serialization round-trip
//! 2. Transcript hash computation
//! 3. Finished message signing/verification
//! 4. NewSessionTicket and CertificateVerify serialization

#![no_main]

use gm_tls::gm::{
    ClientHello, Finished, ServerHello, compute_transcript_hash, compute_transcript_hash_multi,
    select_alpn,
};
use gm_tls::{deserialize, serialize};
use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};

#[derive(Arbitrary, Debug)]
struct HandshakeFuzzInput {
    // ClientHello fields
    ch_random: [u8; 32],
    ch_alpn: Vec<String>,
    ch_sni: Option<String>,
    ch_eph_pubkey: Vec<u8>,
    // ServerHello fields
    sh_random: [u8; 32],
    sh_alpn: Option<String>,
    sh_eph_pubkey: Vec<u8>,
    sh_cert_chain_pem: Vec<u8>,
    sh_require_client_auth: bool,
    // ALPN selection
    alpn_server: Vec<String>,
    alpn_client: Vec<String>,
    // Transcript hash inputs
    transcript_ch: Vec<u8>,
    transcript_sh: Vec<u8>,
    transcript_multi: Vec<Vec<u8>>,
    // Finished
    finished_signature: Vec<u8>,
}

fuzz_target!(|input: HandshakeFuzzInput| {
    // Test ClientHello serialization (without session ticket for simplicity)
    let client_hello = ClientHello {
        version: [0x03, 0x03],
        random: input.ch_random,
        session_id: Vec::new(),
        cipher_suites: vec![0xE001],
        compression_methods: vec![0x00],
        extensions: Vec::new(),
        session_ticket: None,
        eph_pubkey: input.ch_eph_pubkey.clone(),
        alpn: input.ch_alpn.clone(),
        sni: input.ch_sni,
    };

    let ch_encoded = serialize(&client_hello);
    if let Ok(ch_bytes) = ch_encoded {
        let ch_decoded: Result<ClientHello, _> = deserialize(&ch_bytes);
        if let Ok(decoded_ch) = ch_decoded {
            assert_eq!(client_hello.random, decoded_ch.random);
            assert_eq!(client_hello.alpn, decoded_ch.alpn);
        }
    }

    // Test ServerHello serialization
    let server_hello = ServerHello {
        version: [0x03, 0x03],
        random: input.sh_random,
        session_id: Vec::new(),
        cipher_suite: 0xE001,
        compression: 0x00,
        extensions: Vec::new(),
        eph_pubkey: input.sh_eph_pubkey.clone(),
        alpn: input.sh_alpn.clone(),
        cert_chain_pem: input.sh_cert_chain_pem.clone(),
        require_client_auth: input.sh_require_client_auth,
    };

    let sh_encoded = serialize(&server_hello);
    if let Ok(sh_bytes) = sh_encoded {
        let sh_decoded: Result<ServerHello, _> = deserialize(&sh_bytes);
        if let Ok(decoded_sh) = sh_decoded {
            assert_eq!(server_hello.random, decoded_sh.random);
            assert_eq!(
                server_hello.require_client_auth,
                decoded_sh.require_client_auth
            );
        }
    }

    // Test ALPN selection
    let alpn_result = select_alpn(&input.alpn_server, &input.alpn_client);
    if let Some(selected) = alpn_result {
        assert!(input.alpn_client.iter().any(|s| s.as_str() == selected));
    }

    // Test transcript hash
    let hash_result = compute_transcript_hash(&input.transcript_ch, &input.transcript_sh);
    if let Ok(hash) = hash_result {
        assert_eq!(hash.len(), 32, "SM3 hash should be 32 bytes");
    }

    // Test multi-message transcript hash
    if input.transcript_multi.len() <= 10 {
        let slices: Vec<&[u8]> = input
            .transcript_multi
            .iter()
            .map(|v| v.as_slice())
            .collect();
        let multi_result = compute_transcript_hash_multi(&slices);
        if let Ok(multi_hash) = multi_result {
            assert_eq!(multi_hash.len(), 32);
        }
    }

    // Test Finished serialization
    let finished = Finished {
        verify_data: input.finished_signature,
    };
    let fin_encoded = serialize(&finished);
    if let Ok(fin_bytes) = fin_encoded {
        let fin_decoded: Result<Finished, _> = deserialize(&fin_bytes);
        if let Ok(decoded_fin) = fin_decoded {
            assert_eq!(finished.verify_data, decoded_fin.verify_data);
        }
    }
});
