fn main() {
    let mut config = prost_build::Config::new();
    config.type_attribute("Sample", "#[derive(Eq, Hash)]");
    config.type_attribute("Label", "#[derive(Eq, Hash)]");

    config
        .compile_protos(&["src/protos/profile.proto"], &["src/protos"])
        .expect("build profile.proto");
}
