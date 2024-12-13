use anyhow::anyhow;
use inotify::Inotify;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

const SYS_FS_CGROUP_PATH: &str = "/sys/fs/cgroup/";

fn cgroup_name() -> anyhow::Result<String> {
    let data = fs::read_to_string("/proc/self/cgroup")?;
    Ok(data.strip_prefix("0::/").unwrap().trim_end().into())
}
#[derive(Default)]
struct MemoryEvents {
    low: usize,
    high: usize,
    max: usize,
    oom_kill: usize,
    oom_group_kill: usize,
}

impl MemoryEvents {
    fn new(data: &str) -> Self {
        let mut me = MemoryEvents::default();

        for line in data.lines() {
            let mut splitted = line.split(' ');
            let key = splitted.next();
            let value = usize::from_str(splitted.next().unwrap_or("0"));

            match (key, value) {
                (Some("low"), Ok(value)) => {
                    me.low = value;
                }
                (Some("high"), Ok(value)) => {
                    me.high = value;
                }
                (Some("max"), Ok(value)) => {
                    me.max = value;
                }
                (Some("oom_kill"), Ok(value)) => {
                    me.oom_kill = value;
                }
                (Some("oom_group_kill"), Ok(value)) => {
                    me.oom_group_kill = value;
                }
                _ => {}
            }
        }
        me
    }
}
struct CgroupMemoryMonitor {
    initial: MemoryEvents,
    inotify: Inotify,
    memory_events_path: PathBuf,
}

impl CgroupMemoryMonitor {
    fn new() -> anyhow::Result<Self> {
        let memory_events_path = PathBuf::from(SYS_FS_CGROUP_PATH)
            .join(cgroup_name()?)
            .join("memory.events");
        let data = std::fs::read(&memory_events_path)?;
        let data = std::str::from_utf8(&data)?;

        let mut inotify = Inotify::init()?;
        inotify
            .watches()
            .add(&memory_events_path, inotify::WatchMask::MODIFY)?;

        Ok(CgroupMemoryMonitor {
            initial: MemoryEvents::new(&data),
            inotify,
            memory_events_path,
        })
    }

    fn run(&mut self) -> anyhow::Result<()> {
        loop {
            let mut buf = [0; 1024];
            self.inotify.read_events_blocking(&mut buf)?;
            let content = std::fs::read(&self.memory_events_path)?;
            let content = std::str::from_utf8(&content)?;
            println!("{}", content.replace("\n", " "),);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdfdsfsdfs() {

        /*     std::thread::spawn(|| {
            let mut v = vec![];
            for i in 0..10000000 {
                v.push("sdfasdfdafdsafasf".to_string());
            }
        }); */

        // assert_eq!(path.to_string_lossy(), "asdf");
    }
}
