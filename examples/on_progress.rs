fn main() {
    let data = std::fs::read("/Users/tommaso/Desktop/random.dat").unwrap();

    let mut pattern = aobscan::PatternBuilder::from_ida_style("48 8B C0 C1")
        .unwrap()
        .with_all_threads()
        .build();


    pattern.with_progress_handler(|event| {
        // println!("{:#?}", event);
    });

    let now = std::time::Instant::now();

    let res = pattern.scan(data.as_slice(), move |offset| {
        println!("Found pattern at offset {:#02x}", offset);
        true // Return true to continue scanning for other matches
    });

    println!("Elapsed: {}", now.elapsed().as_millis());

    println!("Found: {}", res);
}
