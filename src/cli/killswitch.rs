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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_killswitch_enabled() {
        // Given
        let temp_killswitch_file = tempfile::NamedTempFile::new().unwrap();
        let temp_killswitch_path = temp_killswitch_file.path();
        let killswitch = KillSwitch::new(
            Some(temp_killswitch_path.to_str().expect("").to_string()),
            /*ignore_killswitch*/ false,
        );

        // When/Then
        assert!(killswitch.enabled());
    }

    #[test]
    fn test_killswitch_ignored() {
        // Given
        let temp_killswitch_file = tempfile::NamedTempFile::new().unwrap();
        let temp_killswitch_path = temp_killswitch_file.path();
        let killswitch = KillSwitch::new(
            Some(temp_killswitch_path.to_str().expect("").to_string()),
            /*ignore_killswitch*/ true,
        );

        // When/Then
        assert!(!killswitch.enabled());
    }
}
