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

    #[cfg(not(miri))]
    pub fn for_task(task_id: i32) -> Result<ThreadInfo, anyhow::Error> {
        let task = procfs::process::Process::new(task_id)?;
        let main_task = procfs::process::Process::new(task.status()?.tgid)?.stat()?;
        Ok(ThreadInfo {
            main_thread: task.pid == main_task.pid,
            comm: task.stat()?.comm,
        })
    }

    #[cfg(miri)]
    pub fn for_task(task_id: i32) -> Result<ThreadInfo, anyhow::Error> {
        let stat = std::fs::read_to_string(format!("/proc/{task_id}/stat"))?;
        let (pid, comm) = parse_stat(&stat)?;
        let status = std::fs::read_to_string(format!("/proc/{task_id}/status"))?;
        let tgid = parse_tgid(&status)?;
        Ok(ThreadInfo {
            main_thread: pid == tgid,
            comm,
        })
    }
}

#[cfg(miri)]
fn parse_stat(stat: &str) -> Result<(i32, String), anyhow::Error> {
    let (pid, rest) = stat
        .split_once(" (")
        .ok_or_else(|| anyhow::anyhow!("invalid stat pid"))?;
    let (comm, _) = rest
        .rsplit_once(") ")
        .ok_or_else(|| anyhow::anyhow!("invalid stat comm"))?;
    Ok((pid.parse()?, comm.to_string()))
}

#[cfg(miri)]
fn parse_tgid(status: &str) -> Result<i32, anyhow::Error> {
    let tgid = status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:"))
        .ok_or_else(|| anyhow::anyhow!("missing status tgid"))?;
    Ok(tgid.trim().parse()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(miri))]
    use nix::unistd;
    #[cfg(not(miri))]
    use std::thread;

    #[test]
    fn test_thread_name() {
        #[cfg(miri)]
        {
            let (pid, comm) = parse_stat("123 (funky-thread-na) S 1 2 3").unwrap();
            assert_eq!(pid, 123);
            assert_eq!(comm, "funky-thread-na");
            assert_eq!(parse_tgid("Name:\tmiri\nTgid:\t123\n").unwrap(), 123);
        }

        #[cfg(not(miri))]
        {
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
