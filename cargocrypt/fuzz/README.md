# Fuzz targets

Requires a nightly toolchain and `cargo-fuzz`:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run container_parse -- -max_total_time=60
cargo +nightly fuzz run stream_decrypt  -- -max_total_time=60
cargo +nightly fuzz run scan_content    -- -max_total_time=60
```

| Target | Property |
| --- | --- |
| `container_parse` | `EncryptedSecret::from_bytes` never panics; a parsed version 2 container serialises back to the same bytes |
| `stream_decrypt` | `decrypt_stream` fails cleanly on arbitrary input |
| `scan_content` | the scanner never panics and findings point at valid ranges |

CI runs each target for a short time on every pull request. That catches
shallow crashes; it is not a substitute for a long run.
