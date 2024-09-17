#[derive(Debug, PartialEq, Eq)]
pub struct TaskName {
    pub main_thread: String,
    pub current_thread: String,
}

impl TaskName {
    pub fn errored() -> Self {
        TaskName {
            main_thread: "<could not fetch process name>".into(),
            current_thread: "<could not fetch thread name>".into(),
        }
    }

    pub fn for_task(task_id: i32) -> Result<TaskName, anyhow::Error> {
        let task = procfs::process::Process::new(task_id)?.stat()?;
        let main_task = procfs::process::Process::new(task.pgrp)?.stat()?;
        let thread_name = if task.pid == task.pgrp {
            "<main thread>".to_string()
        } else {
            task.comm
        };
        Ok(TaskName {
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
        let names = TaskName::for_task(unistd::getpgrp().as_raw()).unwrap();
        assert_eq!(names.current_thread, "<main thread>");

        let builder = thread::Builder::new().name("funky-thread-name".to_string());

        builder
            .spawn(|| {
                let names = TaskName::for_task(unistd::gettid().as_raw()).unwrap();
                assert_eq!(names.current_thread, "funky-thread-na");
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
