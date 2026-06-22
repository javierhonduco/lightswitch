#[derive(Debug, PartialEq, Eq)]
pub struct ThreadInfo {
    pub main_thread: bool,
    pub comm: String,
}

impl ThreadInfo {
    pub fn errored() -> Self {
        ThreadInfo {
            main_thread: false,
            comm: "<could not fetch thread name>".into(),
        }
    }

    pub fn for_task(task_id: i32) -> Result<ThreadInfo, anyhow::Error> {
        let task = procfs::process::Process::new(task_id)?;
        let main_task = procfs::process::Process::new(task.status()?.tgid)?.stat()?;
        Ok(ThreadInfo {
            main_thread: task.pid == main_task.pid,
            comm: task.stat()?.comm,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd;
    use std::thread;

    #[test]
    fn test_thread_name() {
        let current_thread = ThreadInfo::for_task(unistd::getpid().as_raw())
            .unwrap()
            .comm;
        assert_eq!(current_thread, "lightswitch_met");

        let builder = thread::Builder::new().name("funky-thread-name".to_string());

        builder
            .spawn(|| {
                let current_thread = ThreadInfo::for_task(unistd::gettid().as_raw())
                    .unwrap()
                    .comm;
                assert_eq!(current_thread, "funky-thread-na");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_errored() {
        // Given
        let task_name = ThreadInfo::errored();

        // When / Then
        assert_eq!(
            task_name.comm,
            String::from("<could not fetch thread name>")
        );
    }
}
