use sdhash::Sdbf;
use std::fs;
use std::path::Path;
use std::process;

fn usage(prog: &str) {
    eprintln!("Usage:");
    eprintln!("  {prog} [FILE]...              Generate sdbf hash(es) and print to stdout");
    eprintln!("  {prog} -c HASHFILE1 HASHFILE2 Compare all hashes in two hash files");
    eprintln!("  {prog} -c -                   Compare all pairs read from stdin");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -c, --compare     Compare mode");
    eprintln!("  -t N              Score threshold for compare output (default: 1)");
    eprintln!("  -h, --help        Show this help");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(|s| s.as_str()).unwrap_or("sdhash");

    if args.len() < 2 {
        usage(prog);
        process::exit(1);
    }

    let mut compare_mode = false;
    let mut threshold = 1;
    let mut files: Vec<String> = Vec::new();
    let mut i = 1usize;

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                usage(prog);
                return;
            }
            "-c" | "--compare" => {
                compare_mode = true;
            }
            "-t" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: -t requires a value");
                    process::exit(1);
                }
                threshold = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("error: -t value must be an integer");
                    process::exit(1);
                });
            }
            arg if arg.starts_with("-t") => {
                threshold = arg[2..].parse().unwrap_or_else(|_| {
                    eprintln!("error: -t value must be an integer");
                    process::exit(1);
                });
            }
            arg => {
                files.push(arg.to_string());
            }
        }
        i += 1;
    }

    if compare_mode {
        run_compare(&files, threshold);
    } else {
        run_generate(&files);
    }
}

fn run_generate(files: &[String]) {
    for path in files {
        match fs::read(path) {
            Err(e) => eprintln!("error reading {path}: {e}"),
            Ok(data) => {
                let name = Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(path);
                match Sdbf::from_data(&data, name) {
                    None => eprintln!(
                        "warning: {path} is too small or produced no features, skipping"
                    ),
                    Some(sdbf) => print!("{sdbf}"),
                }
            }
        }
    }
}

fn run_compare(files: &[String], threshold: u32) {
    if files.is_empty() {
        eprintln!("error: -c requires at least one hash file");
        process::exit(1);
    }

    // Load all hashes from all provided hash files
    let mut sets: Vec<(String, Vec<Sdbf>)> = Vec::new();

    if files.len() == 1 && files[0] == "-" {
        let stdin = std::io::read_to_string(std::io::stdin()).unwrap_or_default();
        let hashes = parse_hash_content(&stdin, "<stdin>");
        sets.push(("<stdin>".to_string(), hashes));
    } else {
        for path in files {
            match fs::read_to_string(path) {
                Err(e) => eprintln!("error reading {path}: {e}"),
                Ok(content) => {
                    let hashes = parse_hash_content(&content, path);
                    sets.push((path.clone(), hashes));
                }
            }
        }
    }

    if sets.is_empty() {
        return;
    }

    if sets.len() == 1 {
        // Compare all pairs within the single set
        let (_, hashes) = &sets[0];
        let n = hashes.len();
        for i in 0..n {
            for j in i + 1..n {
                let score = hashes[i].compare(&hashes[j]);
                if score >= threshold {
                    println!("{}|{}|{}", hashes[i].name(), hashes[j].name(), score);
                }
            }
        }
    } else {
        // Compare all pairs across the two (or more) sets
        for a in 0..sets.len() {
            for b in a + 1..sets.len() {
                for ha in &sets[a].1 {
                    for hb in &sets[b].1 {
                        let score = ha.compare(hb);
                        if score >= threshold {
                            println!("{}|{}|{}", ha.name(), hb.name(), score);
                        }
                    }
                }
            }
        }
    }
}

fn parse_hash_content(content: &str, source: &str) -> Vec<Sdbf> {
    let mut hashes = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match line.parse::<Sdbf>() {
            Ok(h) => hashes.push(h),
            Err(e) => eprintln!("warning: skipping malformed hash in {source}: {e}"),
        }
    }
    hashes
}
