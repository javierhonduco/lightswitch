#[derive(Debug, PartialEq, Eq)]
pub struct TaskInfo {
    pub pid: i32,
    pub main_thread: String,
    pub current_thread: String,
}

impl TaskInfo {
    pub fn errored() -> Self {
        TaskInfo {
            pid: -1,
            main_thread: "<could not fetch process name>".into(),
            current_thread: "<could not fetch thread name>".into(),
        }
    }

    pub fn for_task(task_id: i32) -> Result<TaskInfo, anyhow::Error> {
        let task = procfs::process::Process::new(task_id)?.stat()?;
        let main_task = procfs::process::Process::new(task.pgrp)?.stat()?;
        let thread_name = if task.pid == task.pgrp {
            "<main thread>".to_string()
        } else {
            task.comm
        };
        Ok(TaskInfo {
            pid: task.pgrp,
            main_thread: main_task.comm,
            current_thread: thread_name,
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
        let names = TaskInfo::for_task(unistd::getpgrp().as_raw()).unwrap();
        assert_eq!(names.current_thread, "<main thread>");

        let builder = thread::Builder::new().name("funky-thread-name".to_string());

        builder
            .spawn(|| {
                let names = TaskInfo::for_task(unistd::gettid().as_raw()).unwrap();
                assert_eq!(names.current_thread, "funky-thread-na");
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
