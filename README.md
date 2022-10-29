<h1 align="center">AOBscan 📝</h1>

<div align="center">
  <a href="https://crates.io/crates/aobscan"><img src="https://img.shields.io/crates/v/aobscan.svg"/></a>
  <a href="https://docs.rs/aobscan"><img src="https://docs.rs/aobscan/badge.svg"/></a>
  <a href="https://github.com/sonodima/aobscan/actions?workflow=CI"><img src="https://github.com/sonodima/aobscan/workflows/CI/badge.svg"/></a>
  <a href="https://crates.io/crates/aobscan">
    <img src="https://img.shields.io/crates/d/aobscan?color=pink"/>
  </a>
  <img src="https://img.shields.io/badge/license-MIT-blue.svg"/>
</div>

<br>

> AOBscan is a library for multi-threaded AOB memory scanning, aimed at malware analysis and reverse
> engineering.<br><br>
> This library implements helpful features for scanning for patterns in data slices or object files sections. (allowing
> for extremely fast scans)

## Features

- Single-threaded and multi-threaded scanning
- Match selection using callback functions
- IDA-style patterns: `48 8b ? ? ? 48 8c ?? ?? ?? ??`
- Code-style signatures/masks: (`\x48\x8b\x00\x00\x00`, `..???`)
- Hexadecimal strings: `488b??????`
- Scan for pattern in an object file section _(by name)_

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
aobscan = "0.2"
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

### For a real-world example, check out the [AOBscan CLI](https://github.com/sonodima/aobscan-cli) twin project.

## Benchmark

The results of the `benchmark` example are as follows:

| CPU                | MT Average | ST Average | MT Peak    |
|--------------------|------------|------------|------------|
| Apple M1 Pro (10C) | 10.17 GB/s | 1.42 GB/s  | 12.41 GB/s |
