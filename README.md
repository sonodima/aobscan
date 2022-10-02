<h1 align="center">AOBscan 📝</h1>

<div align="center">
  <a href="https://crates.io/crates/aobscan"><img src="https://img.shields.io/crates/v/aobscan.svg"/></a>
  <a href="https://docs.rs/aobscan"><img src="https://docs.rs/aobscan/badge.svg"/></a>
  <a href="https://github.com/sonodima/aobscan/actions?workflow=CI"><img src="https://github.com/sonodima/aobscan/workflows/CI/badge.svg"/></a>
  <a href="https://crates.io/crates/aobscan"><img src="https://img.shields.io/crates/d/aobscan?color=pink"/></a>


  <img src="https://img.shields.io/badge/license-MIT-blue.svg"/>
</div>

<br>

> AOBscan is a library for multi-threaded AOB memory scanning

## Features

- Single-threaded and multi-threaded scanning
- Match selection using callback functions
- IDA-style patterns: `48 8b ? ? ? 48 8c ?? ?? ?? ??`
- Code-style signatures/masks: (`\x48\x8b\x00\x00\x00`, `..???`)
- Hexadecimal strings: `488b??????`

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
aobscan = "0.1"
```

> <b>Example:</b> Scan for <kbd>48 8B ? ? ?</kbd> in `some.bin` with all the available threads, and stop at the first
> match.

```rust
fn main() {
    let data = include_bytes!("some_file.bin");
    let result = aobscan::Pattern::from_ida_style("48 8B ? ? ? ?")
        .unwrap()
        .with_all_threads()
        .build()
        .scan(data, |offset| {
            println!("Found pattern at offset: 0x{:x}", offset);
            false
        });
}
```

## Benchmark

The results of the `benchmark` example are as follows:

| CPU                | MT        | ST        |
|--------------------|-----------|-----------|
| Apple M1 Pro (10C) | 6.21 GB/s | 0.82 GB/s |
