fn main() {
    let fd = protox::compile(
        [
            "src/protos/profile.proto",
            "src/protos/perfetto_trace.proto",
        ],
        ["src/protos"],
    )
    .expect("compile proto files");

    prost_build::compile_fds(fd).expect("build file descriptors");
}
