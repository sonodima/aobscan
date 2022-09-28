<h1 align="center">AOBscan 📝</h1>

> AOBscan is a library for multi-threaded AOB memory scanning

## Features

- Single-threaded and multi-threaded scanning
- IDA-style & code-style pattern syntax
- Match selection using callback functions

## Usage

```rust
fn main() {
    let data = include_bytes!("some_file.bin");
    let result = aobscan::Pattern::new()
        .ida_style("48 8B ? ? ? ?")
        .unwrap()
        .with_all_threads()
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
| Apple M1 Pro (10C) | 5.77 GB/s | 0.82 GB/s |
