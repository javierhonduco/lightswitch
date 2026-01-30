#[allow(clippy::all)]
pub mod common {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/opentelemetry.proto.common.v1.rs"));
    }
}

#[allow(clippy::all)]
pub mod resource {
    pub mod v1 {
        include!(concat!(
            env!("OUT_DIR"),
            "/opentelemetry.proto.resource.v1.rs"
        ));
    }
}

#[allow(clippy::all)]
pub mod collector {
    pub mod profiles {
        pub mod v1development {
            include!(concat!(
                env!("OUT_DIR"),
                "/opentelemetry.proto.collector.profiles.v1development.rs"
            ));
        }
    }
}

#[allow(clippy::all)]
pub mod profiles {
    pub mod v1development {
        include!(concat!(
            env!("OUT_DIR"),
            "/opentelemetry.proto.profiles.v1development.rs"
        ));
    }
}
