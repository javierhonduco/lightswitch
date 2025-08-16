fn main() {
    let mut config = prost_build::Config::new();
    config
        .compile_protos(&["src/protos/profile.proto"], &["src/protos"])
        .expect("build profile.proto");
}
