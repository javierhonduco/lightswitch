use std::path::Path;
use std::thread;
use std::time::Duration;

use tracing::info;

use crossbeam_channel::{select, tick, Receiver, Sender};
use lightswitch::profiler::ThreadSafeProfiler;

enum RunState {
    Running,
    Stopped,
}

static KILLSWITCH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Runs the profiler in continous profiling mode
/// and provides mechanisms to stop the profiler via
/// a killswitch file or a stop signal.
pub struct Runner {
    profiler: ThreadSafeProfiler,
    profiler_run_state: RunState,
    killswitch_file_path: String,
    runner_stop_signal_receiver: Receiver<()>,
    profiler_stop_signal_sender: Sender<()>,
}

impl Runner {
    pub fn new(
        profiler: ThreadSafeProfiler,
        killswitch_file_path: String,
        runner_stop_signal_receiver: Receiver<()>,
        profiler_stop_signal_sender: Sender<()>,
    ) -> Self {
        Runner {
            profiler,
            profiler_run_state: RunState::Stopped,
            killswitch_file_path,
            runner_stop_signal_receiver,
            profiler_stop_signal_sender,
        }
    }

    fn killswitch_enabled(&self) -> bool {
        let enabled = Path::new(&self.killswitch_file_path).try_exists().unwrap();
        if enabled {
            info!("Killswitch enabled!");
        }
        enabled
    }

    fn start_profiler(&mut self) {
        info!("Starting profiler");
        let p = self.profiler.clone();
        thread::spawn(move || {
            p.lock().unwrap().run(); // This is a blocking call.
        });
        self.profiler_run_state = RunState::Running;
    }

    fn stop_profiler(&mut self) {
        info!("Stopping profiler");
        self.profiler_stop_signal_sender.send(()).unwrap();
        self.profiler_run_state = RunState::Stopped;
    }

    pub fn run(&mut self) {
        if !self.killswitch_enabled() {
            self.start_profiler();
        } else {
            info!("Continuous profiling killswitch enabled. Profiler will not be started");
        }

        let killswitch_ticker = tick(KILLSWITCH_CHECK_INTERVAL);
        loop {
            select! {
                recv(killswitch_ticker) -> _  => {
                    let killswitch_enabled = self.killswitch_enabled();

                    match self.profiler_run_state {
                        RunState::Running => {
                            if killswitch_enabled {
                                self.stop_profiler();
                            }
                        }
                        RunState::Stopped => {
                            if !killswitch_enabled {
                                self.start_profiler();
                            }
                        }
                    }
                },
                recv(self.runner_stop_signal_receiver) -> _ => {
                    self.stop_profiler();
                    break;
                }
            }
        }
    }
}
