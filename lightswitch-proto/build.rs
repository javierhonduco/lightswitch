fn main() {
    // Compile pprof proto.
    let fd = protox::compile(["src/protos/profile.proto"], ["src/protos"])
        .expect("compile profile.proto");
    prost_build::compile_fds(fd).expect("build file descriptors");

    // Compile OTel profiling protos (for devfiler integration).
    let fd = protox::compile(
        ["src/protos/opentelemetry/proto/collector/profiles/v1development/profiles_service.proto"],
        ["src/protos"],
    )
    .expect("compile OTel profiling protos");
    prost_build::compile_fds(fd).expect("build OTel file descriptors");
}
