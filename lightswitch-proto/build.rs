fn main() {
    let fd = protox::compile(["src/protos/profile.proto"], ["src/protos"])
        .expect("compile profile.proto");

    prost_build::compile_fds(fd).expect("build file descriptors");
}
