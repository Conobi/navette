use librustls_mojo::*;

// Helper: create a valid initial keys handle (client, QUIC v1, RFC 9001 dcid).
fn make_handle() -> i32 {
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    let h = rlsm_initial_keys(1, dcid.as_ptr(), dcid.len() as i32, 1);
    assert!(h > 0, "make_handle: expected positive handle, got {h}");
    h
}

// ---------------------------------------------------------------------------
// 1. Invalid handle — encrypt
// ---------------------------------------------------------------------------
#[test]
fn invalid_handle_encrypt() {
    let header = [0xc0u8, 0x00, 0x00, 0x01];
    let mut buf = vec![0u8; 32];
    let rc = rlsm_keys_local_encrypt(
        99999,
        0,
        header.as_ptr(),
        header.len() as i32,
        buf.as_mut_ptr(),
        4,
        buf.len() as i32,
    );
    assert!(rc < 0, "encrypt with invalid handle should return negative, got {rc}");
}

// ---------------------------------------------------------------------------
// 2. Invalid handle — decrypt
// ---------------------------------------------------------------------------
#[test]
fn invalid_handle_decrypt() {
    let header = [0xc0u8, 0x00, 0x00, 0x01];
    let mut buf = vec![0u8; 32];
    let rc = rlsm_keys_remote_decrypt(
        99999,
        0,
        header.as_ptr(),
        header.len() as i32,
        buf.as_mut_ptr(),
        buf.len() as i32,
    );
    assert!(rc < 0, "decrypt with invalid handle should return negative, got {rc}");
}

// ---------------------------------------------------------------------------
// 3. Invalid handle — header protect
// ---------------------------------------------------------------------------
#[test]
fn invalid_handle_header_protect() {
    let sample = [0x01u8; 16];
    let mut first_byte: u8 = 0xC3;
    let mut pn_bytes = [0x00u8; 4];
    let rc = rlsm_keys_local_header_protect(
        99999,
        sample.as_ptr(),
        sample.len() as i32,
        &mut first_byte,
        pn_bytes.as_mut_ptr(),
        pn_bytes.len() as i32,
    );
    assert!(rc < 0, "header protect with invalid handle should return negative, got {rc}");
}

// ---------------------------------------------------------------------------
// 4. Invalid handle — tag_len
//    (Already tested in test_quic.rs as `keys_tag_len_invalid_handle`, but
//     included here for completeness as part of the safety test suite.)
// ---------------------------------------------------------------------------
#[test]
fn invalid_handle_tag_len() {
    let rc = rlsm_keys_tag_len(99999);
    assert!(rc < 0, "tag_len on invalid handle should return negative, got {rc}");
}

// ---------------------------------------------------------------------------
// 5. Double free — second free returns non-zero (handle no longer present)
// ---------------------------------------------------------------------------
#[test]
fn double_free_returns_nonzero() {
    let h = make_handle();
    let first = rlsm_keys_free(h);
    assert_eq!(first, 0, "first free should succeed");
    let second = rlsm_keys_free(h);
    assert!(second != 0, "second free on already-freed handle should return non-zero, got {second}");
}

// ---------------------------------------------------------------------------
// 6. Use after free — tag_len after free returns negative
// ---------------------------------------------------------------------------
#[test]
fn use_after_free_tag_len() {
    let h = make_handle();
    let rc = rlsm_keys_free(h);
    assert_eq!(rc, 0, "free should succeed");
    let tag = rlsm_keys_tag_len(h);
    assert!(tag < 0, "tag_len after free should return negative, got {tag}");
}

// ---------------------------------------------------------------------------
// 7. Buffer capacity too small — encrypt fails when capacity < payload + tag
// ---------------------------------------------------------------------------
#[test]
fn buffer_capacity_too_small() {
    let h = make_handle();
    let header = [0xc0u8, 0x00, 0x00, 0x01];
    let tag_len = rlsm_keys_tag_len(h) as usize;
    let payload = b"hello";

    // Allocate exactly payload_len bytes — no room for the tag.
    let mut buf = vec![0u8; payload.len()];
    buf[..payload.len()].copy_from_slice(payload);

    let rc = rlsm_keys_local_encrypt(
        h,
        0,
        header.as_ptr(),
        header.len() as i32,
        buf.as_mut_ptr(),
        payload.len() as i32,
        // capacity == payload_len, which is less than payload_len + tag_len
        buf.len() as i32,
    );
    assert!(
        rc < 0,
        "encrypt should fail when buf_capacity ({}) < payload_len ({}) + tag_len ({}), got rc={}",
        buf.len(),
        payload.len(),
        tag_len,
        rc
    );

    rlsm_keys_free(h);
}

// ---------------------------------------------------------------------------
// 8. Negative header length — encrypt rejects header_len = -1
// ---------------------------------------------------------------------------
#[test]
fn negative_header_len_encrypt() {
    let h = make_handle();
    let header = [0xc0u8, 0x00, 0x00, 0x01];
    let mut buf = vec![0u8; 32];

    let rc = rlsm_keys_local_encrypt(
        h,
        0,
        header.as_ptr(),
        -1, // negative header_len
        buf.as_mut_ptr(),
        4,
        buf.len() as i32,
    );
    assert!(rc < 0, "encrypt with negative header_len should return negative, got {rc}");

    rlsm_keys_free(h);
}

// ---------------------------------------------------------------------------
// 9. Null pointer — rlsm_initial_keys with null dcid returns negative
//    (Already tested in test_quic.rs as `initial_keys_null_dcid`, but
//     included here for completeness as part of the safety test suite.)
// ---------------------------------------------------------------------------
#[test]
fn null_dcid_pointer_returns_negative() {
    let h = rlsm_initial_keys(1, std::ptr::null(), 8, 1);
    assert!(h < 0, "null dcid should return negative, got {h}");
}

// ---------------------------------------------------------------------------
// 10. Nonce reuse rejected — encrypt with pn=0 twice → second returns negative
//     (Already tested in test_quic.rs as `encrypt_nonce_reuse_rejected`, but
//      included here for completeness as part of the safety test suite.)
// ---------------------------------------------------------------------------
#[test]
fn nonce_reuse_rejected() {
    let h = make_handle();
    let header = [0xc0u8, 0x00, 0x00, 0x01];
    let tag_len = rlsm_keys_tag_len(h) as usize;
    let plaintext = b"test";

    let mut buf = vec![0u8; plaintext.len() + tag_len];
    buf[..plaintext.len()].copy_from_slice(plaintext);

    // First encrypt at pn=0 should succeed.
    let ct_len = rlsm_keys_local_encrypt(
        h,
        0,
        header.as_ptr(),
        header.len() as i32,
        buf.as_mut_ptr(),
        plaintext.len() as i32,
        buf.len() as i32,
    );
    assert!(ct_len > 0, "first encrypt should succeed, got {ct_len}");

    // Second encrypt at pn=0 (nonce reuse) must be rejected.
    let mut buf2 = vec![0u8; plaintext.len() + tag_len];
    buf2[..plaintext.len()].copy_from_slice(plaintext);
    let rc = rlsm_keys_local_encrypt(
        h,
        0,
        header.as_ptr(),
        header.len() as i32,
        buf2.as_mut_ptr(),
        plaintext.len() as i32,
        buf2.len() as i32,
    );
    assert!(rc < 0, "second encrypt at same pn should be rejected, got {rc}");

    rlsm_keys_free(h);
}

// ---------------------------------------------------------------------------
// 11. Last error populated — after any failure, rlsm_last_error returns
//     a non-empty NUL-terminated message.
// ---------------------------------------------------------------------------
#[test]
fn last_error_populated_after_failure() {
    // Trigger a failure (invalid handle).
    let rc = rlsm_keys_tag_len(99999);
    assert!(rc < 0);

    // Retrieve the error message.
    let mut buf = vec![0u8; 256];
    let written = rlsm_last_error(buf.as_mut_ptr(), buf.len() as i32);
    assert!(written > 0, "rlsm_last_error should return > 0 after a failure, got {written}");

    // The returned value is the byte count including the NUL terminator.
    let msg_len = (written - 1) as usize; // exclude NUL
    let msg = std::str::from_utf8(&buf[..msg_len]).expect("error message should be valid UTF-8");
    assert!(!msg.is_empty(), "error message should not be empty");
}
