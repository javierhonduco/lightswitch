use std::path::Path;

const KILLSWITCH_FILE_PATH: &str = "/tmp/lightswitch/killswitch";

pub struct KillSwitch {
    killswitch_path: String,
    ignore_killswitch: bool,
}

impl KillSwitch {
    pub fn new(killswitch_path_override: Option<String>, ignore_killswitch: bool) -> Self {
        let killswitch_path = match killswitch_path_override {
            Some(path) if !path.is_empty() => path,
            _ => KILLSWITCH_FILE_PATH.to_string(),
        };
        KillSwitch {
            killswitch_path,
            ignore_killswitch,
        }
    }

    pub fn enabled(&self) -> bool {
        !self.ignore_killswitch && Path::new(&self.killswitch_path).try_exists().unwrap()
    }
}
