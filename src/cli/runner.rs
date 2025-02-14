use std::path::Path;
use std::thread;
use std::time::Duration;

use crossbeam_channel::{tick, Sender};
use lightswitch::profiler::Profiler;

enum RunState {
    Running,
    Stopped,
}

pub struct Runner {
    profiler: Profiler,
    run_state: RunState,
    killswitch_file_path: String,
    stop_signal_sender: Sender<()>,
}

impl Runner {
    pub fn new(profiler: Profiler, killswitch_file_path: String, stop_signal_sender: Sender<()>) -> Self {
        return Runner {
            profiler: profiler,
            run_state: RunState::Stopped,
            killswitch_file_path: killswitch_file_path,
            stop_signal_sender: stop_signal_sender,
        };
    }

    fn killswitch_enabled(&self) -> bool {
        return Path::new(&self.killswitch_file_path).exists();
    }

    // Kill the profiler using Ctrl+C
    pub fn start(&mut self) {
        // Start the profiler
        // TODO: Move this to a different thread
        // thread::spawn(|| move )
        self.profiler.run();
        // terminate the profiler if the stop signal is received

        // On the main thread, every n seconds check the kill switch
        let ticker = tick(Duration::from_secs(10));
        loop {
            let _ = ticker.recv().unwrap();

            if self.killswitch_enabled() {
                match self.run_state {
                    RunState::Running => {
                        self.stop_signal_sender.send(()).unwrap();
                        self.run_state = RunState::Stopped;
                    }
                    RunState::Stopped => {
                        // Do nothing
                    }
                }
            } else {
                match self.run_state {
                    RunState::Running => {
                        // Do nothing
                    }
                    RunState::Stopped => {
                        self.profiler.run();
                        self.run_state = RunState::Running;
                    }
                }
            }
        }
    }
}
