use librustls_mojo::*;

#[test]
fn initial_keys_raw_client_rfc9001_a1() {
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 32];
    let mut key_len: i32 = 0;
    let mut iv_len: i32 = 0;
    let mut hp_len: i32 = 0;

    let rc = rlsm_initial_keys_raw(
        1,
        dcid.as_ptr(),
        dcid.len() as i32,
        1,
        key.as_mut_ptr(),
        &mut key_len,
        iv.as_mut_ptr(),
        &mut iv_len,
        hp.as_mut_ptr(),
        &mut hp_len,
    );

    assert_eq!(rc, 0, "should succeed");
    assert_eq!(
        hex::encode(&key[..key_len as usize]),
        "1f369613dd76d5467730efcbe3b1a22d"
    );
    assert_eq!(
        hex::encode(&iv[..iv_len as usize]),
        "fa044b2f42a3fd3b46fb255c"
    );
    assert_eq!(
        hex::encode(&hp[..hp_len as usize]),
        "9f50449e04a0e810283a1e9933adedd2"
    );
}

#[test]
fn initial_keys_raw_server_rfc9001_a1() {
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 32];
    let mut key_len: i32 = 0;
    let mut iv_len: i32 = 0;
    let mut hp_len: i32 = 0;

    let rc = rlsm_initial_keys_raw(
        1,
        dcid.as_ptr(),
        dcid.len() as i32,
        0,
        key.as_mut_ptr(),
        &mut key_len,
        iv.as_mut_ptr(),
        &mut iv_len,
        hp.as_mut_ptr(),
        &mut hp_len,
    );

    assert_eq!(rc, 0);
    assert_eq!(
        hex::encode(&key[..key_len as usize]),
        "cf3a5331653c364c88f0f379b6067e37"
    );
    assert_eq!(
        hex::encode(&iv[..iv_len as usize]),
        "0ac1493ca1905853b0bba03e"
    );
    assert_eq!(
        hex::encode(&hp[..hp_len as usize]),
        "c206b8d9b9f0f37644430b490eeaa314"
    );
}

#[test]
fn initial_keys_returns_valid_handle() {
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    let handle = rlsm_initial_keys(1, dcid.as_ptr(), dcid.len() as i32, 1);
    assert!(handle > 0, "handle should be positive, got {handle}");
    let tag = rlsm_keys_tag_len(handle);
    assert_eq!(tag, 16);
    let rc = rlsm_keys_free(handle);
    assert_eq!(rc, 0);
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    // Client encrypts
    let client_h = rlsm_initial_keys(1, dcid.as_ptr(), dcid.len() as i32, 1);
    assert!(client_h > 0, "client handle should be positive");
    // Server decrypts
    let server_h = rlsm_initial_keys(1, dcid.as_ptr(), dcid.len() as i32, 0);
    assert!(server_h > 0, "server handle should be positive");

    let header = [0xc0u8, 0x00, 0x00, 0x01]; // dummy header
    let plaintext = b"Hello QUIC!";
    let tag_len = rlsm_keys_tag_len(client_h) as usize;

    // Create buffer with space for plaintext + tag
    let mut buf = vec![0u8; plaintext.len() + tag_len];
    buf[..plaintext.len()].copy_from_slice(plaintext);

    // Encrypt with client's local keys
    let ct_len = rlsm_keys_local_encrypt(
        client_h,
        0,
        header.as_ptr(),
        header.len() as i32,
        buf.as_mut_ptr(),
        plaintext.len() as i32,
        buf.len() as i32,
    );
    assert!(ct_len > 0, "encrypt should succeed, got {ct_len}");
    assert_eq!(ct_len as usize, plaintext.len() + tag_len);

    // Decrypt with server's remote keys (server's remote = client's local)
    let pt_len = rlsm_keys_remote_decrypt(
        server_h,
        0,
        header.as_ptr(),
        header.len() as i32,
        buf.as_mut_ptr(),
        ct_len,
    );
    assert_eq!(pt_len as usize, plaintext.len());
    assert_eq!(&buf[..pt_len as usize], plaintext);

    rlsm_keys_free(client_h);
    rlsm_keys_free(server_h);
}

#[test]
fn header_protect_unprotect_roundtrip() {
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    let client_h = rlsm_initial_keys(1, dcid.as_ptr(), dcid.len() as i32, 1);
    assert!(client_h > 0);
    let server_h = rlsm_initial_keys(1, dcid.as_ptr(), dcid.len() as i32, 0);
    assert!(server_h > 0);

    // A 16-byte sample (AES-128 block size)
    let sample = [0x01u8; 16];
    let mut first_byte: u8 = 0xC3; // long header form
    let original_first = first_byte;
    let mut pn_bytes = [0x00u8, 0x00, 0x00, 0x01]; // 4-byte packet number
    let original_pn = pn_bytes;

    // Protect with client's local header keys
    let rc = rlsm_keys_local_header_protect(
        client_h,
        sample.as_ptr(),
        sample.len() as i32,
        &mut first_byte,
        pn_bytes.as_mut_ptr(),
        pn_bytes.len() as i32,
    );
    assert_eq!(rc, 0, "header protect should succeed");

    // Something should have changed
    assert!(
        first_byte != original_first || pn_bytes != original_pn,
        "header protection should modify first byte or pn bytes"
    );

    // Unprotect with server's remote header keys (server's remote = client's local)
    let rc = rlsm_keys_remote_header_unprotect(
        server_h,
        sample.as_ptr(),
        sample.len() as i32,
        &mut first_byte,
        pn_bytes.as_mut_ptr(),
        pn_bytes.len() as i32,
    );
    assert_eq!(rc, 0, "header unprotect should succeed");

    // Should be back to original
    assert_eq!(first_byte, original_first);
    assert_eq!(pn_bytes, original_pn);

    rlsm_keys_free(client_h);
    rlsm_keys_free(server_h);
}

#[test]
fn initial_keys_negative_dcid_len() {
    let dcid = [0u8; 8];
    let h = rlsm_initial_keys(1, dcid.as_ptr(), -1, 1);
    assert!(h < 0);
}

#[test]
fn initial_keys_null_dcid() {
    let h = rlsm_initial_keys(1, std::ptr::null(), 8, 1);
    assert!(h < 0);
}

#[test]
fn keys_free_invalid_handle() {
    let rc = rlsm_keys_free(999999);
    assert!(rc < 0, "freeing invalid handle should return error");
}

#[test]
fn keys_tag_len_invalid_handle() {
    let rc = rlsm_keys_tag_len(999999);
    assert!(rc < 0, "tag_len on invalid handle should return error");
}

#[test]
fn encrypt_nonce_reuse_rejected() {
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    let handle = rlsm_initial_keys(1, dcid.as_ptr(), dcid.len() as i32, 1);
    assert!(handle > 0);

    let header = [0xc0u8, 0x00, 0x00, 0x01];
    let tag_len = rlsm_keys_tag_len(handle) as usize;
    let plaintext = b"test";

    // First encrypt at pn=0 should succeed
    let mut buf = vec![0u8; plaintext.len() + tag_len];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ct_len = rlsm_keys_local_encrypt(
        handle,
        0,
        header.as_ptr(),
        header.len() as i32,
        buf.as_mut_ptr(),
        plaintext.len() as i32,
        buf.len() as i32,
    );
    assert!(ct_len > 0);

    // Second encrypt at pn=0 (reuse) should fail
    let mut buf2 = vec![0u8; plaintext.len() + tag_len];
    buf2[..plaintext.len()].copy_from_slice(plaintext);
    let ct_len2 = rlsm_keys_local_encrypt(
        handle,
        0,
        header.as_ptr(),
        header.len() as i32,
        buf2.as_mut_ptr(),
        plaintext.len() as i32,
        buf2.len() as i32,
    );
    assert!(ct_len2 < 0, "nonce reuse should be rejected");

    rlsm_keys_free(handle);
}

#[test]
fn initial_keys_unsupported_version() {
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    let h = rlsm_initial_keys(99, dcid.as_ptr(), dcid.len() as i32, 1);
    assert!(h < 0, "unsupported version should return error");
}
