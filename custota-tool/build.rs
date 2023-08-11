use std::{env, ffi::OsStr, fs, io, path::Path};

use pb_rs::{types::FileDescriptor, ConfigBuilder};

fn main() {
    let out_dir = Path::new(&env::var("OUT_DIR").unwrap()).join("protobuf");
    let in_dir = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("..")
        .join("protobuf");

    println!("cargo:rerun-if-changed={}", in_dir.to_str().unwrap());

    let mut protos = Vec::new();

    for entry in fs::read_dir(&in_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension() == Some(OsStr::new("proto")) {
            println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
            protos.push(path);
        }
    }

    match fs::remove_dir_all(&out_dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        r => r.unwrap(),
    }

    fs::create_dir_all(&out_dir).unwrap();

    let config = ConfigBuilder::new(&protos, None, Some(&out_dir), &[in_dir])
        .unwrap()
        .dont_use_cow(true)
        .build();

    FileDescriptor::run(&config).unwrap();
}
