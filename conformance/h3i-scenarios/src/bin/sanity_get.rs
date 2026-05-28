//! Sanity scenario: GET / against `hello_h3_server` on 127.0.0.1:4433.
//!
//! Asserts navette's H3 stack completes a QUIC + HTTP/3 handshake and returns
//! a HEADERS frame with `:status` set on stream 0. Exits 0 on success, 1 on
//! any failure mode (no handshake, wrong status, timeout before HEADERS).
//!
//! This scenario gates the h3i harness itself — if it fails, no downstream
//! conformance scenario can be trusted.

use h3i::actions::h3::{send_headers_frame, Action, StreamEvent, StreamEventType, WaitType};
use h3i::client::sync_client;
use h3i::quiche::h3::{Header, NameValue};
use h3i_scenarios::default_local_config;

const STREAM_ID: u64 = 0;

fn main() {
    let config = default_local_config(4433);

    let headers = vec![
        Header::new(b":method", b"GET"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", b"127.0.0.1"),
        Header::new(b":path", b"/"),
    ];

    let actions = vec![
        send_headers_frame(STREAM_ID, true, headers),
        Action::Wait {
            wait_type: WaitType::StreamEvent(StreamEvent {
                stream_id: STREAM_ID,
                event_type: StreamEventType::Headers,
            }),
        },
    ];

    let summary = match sync_client::connect(config, actions, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sanity_get: connect failed: {e:?}");
            std::process::exit(1);
        }
    };

    let received = summary.stream_map.headers_on_stream(STREAM_ID);
    let got_200 = received.iter().any(|eh| {
        eh.headers()
            .iter()
            .any(|h| h.name() == b":status" && h.value() == b"200")
    });

    if got_200 {
        println!("sanity_get: PASS (handshake + 200 OK observed on stream 0)");
        std::process::exit(0);
    } else {
        eprintln!("sanity_get: FAIL (no :status=200 HEADERS frame on stream 0)");
        eprintln!("frames seen: {received:?}");
        std::process::exit(1);
    }
}
