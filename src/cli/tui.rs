use std::collections::{HashMap, VecDeque};
use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Terminal;

use lightswitch::collector::{Collector, ThreadSafeCollector};
use lightswitch::ksym::{Ksym, KsymIter};
use lightswitch::process::{ObjectFileInfo, Pid, ProcessInfo};
use lightswitch::profile::{AggregatedProfile, RawAggregatedProfile};
use lightswitch_object::ExecutableId;

/// Kernel symbol resolver using /proc/kallsyms
pub struct KernelSymbols {
    symbols: Vec<Ksym>,
}

impl KernelSymbols {
    pub fn new() -> Self {
        let symbols: Vec<Ksym> = KsymIter::from_kallsyms().collect();
        Self { symbols }
    }

    /// Look up a kernel address and return the symbol name
    pub fn resolve(&self, addr: u64) -> Option<&str> {
        if self.symbols.is_empty() {
            return None;
        }

        // Binary search to find the symbol containing this address
        let idx = match self.symbols.binary_search_by_key(&addr, |s| s.start_addr) {
            Ok(i) => i,
            Err(i) if i > 0 => i - 1,
            Err(_) => return None,
        };

        // Check if the address is within a reasonable range of the symbol
        let sym = &self.symbols[idx];
        if addr >= sym.start_addr {
            Some(&sym.symbol_name)
        } else {
            None
        }
    }
}

/// Statistics for live display
#[derive(Default)]
pub struct LiveStats {
    pub total_samples: AtomicU64,
    pub samples_this_window: AtomicU64,
    pub unique_stacks: AtomicU64,
    pub processes_seen: AtomicU64,
}

/// Entry for function/stack statistics
#[derive(Clone, Debug)]
pub struct FunctionEntry {
    pub name: String,
    pub count: u64,
    pub percentage: f64,
}

/// Entry for process statistics
#[derive(Clone, Debug)]
pub struct ProcessEntry {
    pub pid: Pid,
    pub name: String,
    pub count: u64,
    pub percentage: f64,
}

/// Maximum number of 1-second sparkline buckets to retain (1 minute of history).
const SPARKLINE_MAX_BUCKETS: usize = 60;

/// Unicode block characters for sparkline rendering, indexed 0-7 by intensity.
const SPARKLINE_CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// A time-series ring buffer of per-second sample counts.
#[derive(Clone, Debug, Default)]
pub struct SparklineData {
    buckets: VecDeque<u64>,
    last_epoch_sec: u64,
}

impl SparklineData {
    pub fn record(&mut self, collected_at_ns: u64, count: u64) {
        let epoch_sec = collected_at_ns / 1_000_000_000;

        if self.buckets.is_empty() {
            self.buckets.push_back(count);
            self.last_epoch_sec = epoch_sec;
            return;
        }

        if epoch_sec == self.last_epoch_sec {
            if let Some(last) = self.buckets.back_mut() {
                *last += count;
            }
        } else if epoch_sec > self.last_epoch_sec {
            let gap = (epoch_sec - self.last_epoch_sec).min(SPARKLINE_MAX_BUCKETS as u64);
            for _ in 1..gap {
                self.buckets.push_back(0);
                if self.buckets.len() > SPARKLINE_MAX_BUCKETS {
                    self.buckets.pop_front();
                }
            }
            self.buckets.push_back(count);
            self.last_epoch_sec = epoch_sec;
        }

        while self.buckets.len() > SPARKLINE_MAX_BUCKETS {
            self.buckets.pop_front();
        }
    }

    pub fn render(&self, width: usize) -> String {
        if self.buckets.is_empty() {
            return " ".repeat(width);
        }

        let max_val = self.buckets.iter().copied().max().unwrap_or(1).max(1);
        let start = self.buckets.len().saturating_sub(width);
        let mut result = String::with_capacity(width * 4);

        for i in start..self.buckets.len() {
            let val = self.buckets[i];
            let idx = ((val as f64 / max_val as f64) * 7.0) as usize;
            result.push(SPARKLINE_CHARS[idx.min(7)]);
        }

        let rendered_len = self.buckets.len() - start;
        for _ in rendered_len..width {
            result.push(' ');
        }

        result
    }

    pub fn merge(&mut self, other: &SparklineData) {
        if other.buckets.is_empty() {
            return;
        }
        if self.buckets.is_empty() {
            *self = other.clone();
            return;
        }

        let len = self.buckets.len().max(other.buckets.len());
        let mut merged = VecDeque::with_capacity(len);
        for i in 0..len {
            let a = if i + self.buckets.len() >= len {
                self.buckets[i + self.buckets.len() - len]
            } else {
                0
            };
            let b = if i + other.buckets.len() >= len {
                other.buckets[i + other.buckets.len() - len]
            } else {
                0
            };
            merged.push_back(a + b);
        }
        self.buckets = merged;
        self.last_epoch_sec = self.last_epoch_sec.max(other.last_epoch_sec);
    }
}

/// Per-thread data stored in LiveCollector for drill-down.
#[derive(Clone, Debug)]
pub struct ThreadData {
    pub tid: Pid,
    pub thread_name: String,
    pub sample_count: u64,
    pub sparkline: SparklineData,
    pub function_counts: HashMap<String, u64>,
    pub function_sparklines: HashMap<String, SparklineData>,
}

/// Per-process data that includes thread-level detail.
#[derive(Clone, Debug)]
pub struct ProcessDetailData {
    #[allow(dead_code)]
    pub pid: Pid,
    pub name: String,
    pub total_samples: u64,
    pub sparkline: SparklineData,
    pub threads: HashMap<Pid, ThreadData>,
}

/// How to group rows in the drill-down view.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GroupBy {
    ThreadName,
    Tid,
    Function,
}

impl GroupBy {
    pub fn next(self) -> Self {
        match self {
            GroupBy::ThreadName => GroupBy::Tid,
            GroupBy::Tid => GroupBy::Function,
            GroupBy::Function => GroupBy::ThreadName,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            GroupBy::ThreadName => "Thread Name",
            GroupBy::Tid => "TID",
            GroupBy::Function => "Function",
        }
    }
}

/// An entry in the drill-down table after grouping.
#[derive(Clone, Debug)]
pub struct DrillDownEntry {
    pub key: String,
    pub count: u64,
    pub percentage: f64,
    pub sparkline: SparklineData,
}

/// Which view the TUI is showing.
#[derive(Clone, Debug, PartialEq)]
pub enum ViewMode {
    Overview,
    ProcessDetail { pid: Pid, group_by: GroupBy },
}

/// Live collector that accumulates data for the TUI
pub struct LiveCollector {
    pub stats: Arc<LiveStats>,
    #[allow(dead_code)]
    should_stop: Arc<AtomicBool>,
    function_counts: HashMap<Vec<u64>, (String, u64)>,
    process_counts: HashMap<Pid, u64>,
    process_names: HashMap<Pid, String>,
    procs: HashMap<Pid, ProcessInfo>,
    objs: HashMap<ExecutableId, ObjectFileInfo>,
    window_start: Instant,
    kernel_symbols: KernelSymbols,
    symbol_cache: HashMap<u64, String>,
    process_detail: HashMap<Pid, ProcessDetailData>,
    thread_names: HashMap<Pid, String>,
}

impl LiveCollector {
    pub fn new(stats: Arc<LiveStats>, should_stop: Arc<AtomicBool>) -> Self {
        Self {
            stats,
            should_stop,
            function_counts: HashMap::new(),
            process_counts: HashMap::new(),
            process_names: HashMap::new(),
            procs: HashMap::new(),
            objs: HashMap::new(),
            window_start: Instant::now(),
            kernel_symbols: KernelSymbols::new(),
            symbol_cache: HashMap::new(),
            process_detail: HashMap::new(),
            thread_names: HashMap::new(),
        }
    }

    /// Resolve an address to a symbol name
    fn resolve_symbol(&mut self, addr: u64, pid: Pid, is_kernel: bool) -> String {
        // Check cache first
        if let Some(cached) = self.symbol_cache.get(&addr) {
            return cached.clone();
        }

        let symbol = if is_kernel {
            // Kernel address - use kallsyms
            self.kernel_symbols
                .resolve(addr)
                .map(|s| format!("[k] {}", s))
                .unwrap_or_else(|| format!("[k] 0x{:x}", addr))
        } else {
            // User-space address - try to find the binary from mappings
            if let Some(proc_info) = self.procs.get(&pid) {
                if let Some(mapping) = proc_info.mappings.for_address(&addr) {
                    if let Some(obj_info) = self.objs.get(&mapping.executable_id) {
                        // Get the binary name from the path
                        let binary_name = obj_info
                            .path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("???");
                        let offset = addr.saturating_sub(mapping.start_addr);
                        format!("{}+0x{:x}", binary_name, offset)
                    } else {
                        format!("0x{:x}", addr)
                    }
                } else {
                    format!("0x{:x}", addr)
                }
            } else {
                format!("0x{:x}", addr)
            }
        };

        // Cache the result (limit cache size to prevent memory issues)
        if self.symbol_cache.len() < 100_000 {
            self.symbol_cache.insert(addr, symbol.clone());
        }

        symbol
    }

    pub fn get_top_functions(&self, limit: usize) -> Vec<FunctionEntry> {
        let total: u64 = self.function_counts.values().map(|(_, c)| c).sum();
        if total == 0 {
            return vec![];
        }

        let mut entries: Vec<_> = self
            .function_counts
            .values()
            .map(|(name, count)| FunctionEntry {
                name: name.clone(),
                count: *count,
                percentage: (*count as f64 / total as f64) * 100.0,
            })
            .collect();

        entries.sort_by(|a, b| b.count.cmp(&a.count));
        entries.truncate(limit);
        entries
    }

    pub fn get_top_processes(&self, limit: usize) -> Vec<ProcessEntry> {
        let total: u64 = self.process_counts.values().sum();
        if total == 0 {
            return vec![];
        }

        let mut entries: Vec<_> = self
            .process_counts
            .iter()
            .map(|(pid, count)| ProcessEntry {
                pid: *pid,
                name: self
                    .process_names
                    .get(pid)
                    .cloned()
                    .unwrap_or_else(|| format!("<{}>", pid)),
                count: *count,
                percentage: (*count as f64 / total as f64) * 100.0,
            })
            .collect();

        entries.sort_by(|a, b| b.count.cmp(&a.count));
        entries.truncate(limit);
        entries
    }

    pub fn samples_per_second(&self) -> f64 {
        let elapsed = self.window_start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.stats.samples_this_window.load(Ordering::Relaxed) as f64 / elapsed
        } else {
            0.0
        }
    }

    pub fn get_process_detail(
        &self,
        pid: Pid,
        group_by: GroupBy,
        limit: usize,
    ) -> Vec<DrillDownEntry> {
        let Some(detail) = self.process_detail.get(&pid) else {
            return vec![];
        };

        let total = detail.total_samples;
        if total == 0 {
            return vec![];
        }

        let mut entries: Vec<DrillDownEntry> = match group_by {
            GroupBy::Tid => detail
                .threads
                .values()
                .map(|td| DrillDownEntry {
                    key: format!("{} ({})", td.tid, td.thread_name),
                    count: td.sample_count,
                    percentage: (td.sample_count as f64 / total as f64) * 100.0,
                    sparkline: td.sparkline.clone(),
                })
                .collect(),
            GroupBy::ThreadName => {
                let mut by_name: HashMap<String, (u64, SparklineData)> = HashMap::new();
                for td in detail.threads.values() {
                    let entry = by_name
                        .entry(td.thread_name.clone())
                        .or_insert_with(|| (0, SparklineData::default()));
                    entry.0 += td.sample_count;
                    entry.1.merge(&td.sparkline);
                }
                by_name
                    .into_iter()
                    .map(|(name, (count, sparkline))| DrillDownEntry {
                        key: name,
                        count,
                        percentage: (count as f64 / total as f64) * 100.0,
                        sparkline,
                    })
                    .collect()
            }
            GroupBy::Function => {
                let mut by_func: HashMap<String, (u64, SparklineData)> = HashMap::new();
                for td in detail.threads.values() {
                    for (func, count) in &td.function_counts {
                        let entry = by_func
                            .entry(func.clone())
                            .or_insert_with(|| (0, SparklineData::default()));
                        entry.0 += count;
                    }
                    for (func, sparkline) in &td.function_sparklines {
                        let entry = by_func
                            .entry(func.clone())
                            .or_insert_with(|| (0, SparklineData::default()));
                        entry.1.merge(sparkline);
                    }
                }
                by_func
                    .into_iter()
                    .map(|(name, (count, sparkline))| DrillDownEntry {
                        key: name,
                        count,
                        percentage: (count as f64 / total as f64) * 100.0,
                        sparkline,
                    })
                    .collect()
            }
        };

        entries.sort_by(|a, b| b.count.cmp(&a.count));
        entries.truncate(limit);
        entries
    }

    pub fn get_process_summary(&self, pid: Pid) -> Option<(String, u64, SparklineData)> {
        self.process_detail
            .get(&pid)
            .map(|d| (d.name.clone(), d.total_samples, d.sparkline.clone()))
    }
}

impl Collector for LiveCollector {
    fn collect(
        &mut self,
        profile: RawAggregatedProfile,
        procs: &HashMap<Pid, ProcessInfo>,
        objs: &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        for (k, v) in procs {
            self.procs.insert(*k, v.clone());
        }
        for (k, v) in objs {
            self.objs.insert(*k, v.clone());
        }

        for sample in &profile {
            let count = sample.count;
            self.stats.total_samples.fetch_add(count, Ordering::Relaxed);
            self.stats
                .samples_this_window
                .fetch_add(count, Ordering::Relaxed);

            let pid = sample.sample.pid;
            let tid = sample.sample.tid;
            let collected_at = sample.sample.collected_at;
            *self.process_counts.entry(pid).or_insert(0) += count;

            // Try to get process name from /proc
            let process_name = if let std::collections::hash_map::Entry::Vacant(e) =
                self.process_names.entry(pid)
            {
                if let Ok(name) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
                    let name = name.trim().to_string();
                    e.insert(name.clone());
                    name
                } else {
                    format!("<{}>", pid)
                }
            } else {
                self.process_names
                    .get(&pid)
                    .cloned()
                    .unwrap_or_else(|| format!("<{}>", pid))
            };

            // Cache thread name
            if let std::collections::hash_map::Entry::Vacant(e) = self.thread_names.entry(tid) {
                if let Ok(name) = std::fs::read_to_string(format!("/proc/{}/comm", tid)) {
                    e.insert(name.trim().to_string());
                } else {
                    e.insert(format!("<{}>", tid));
                }
            }
            let thread_name = self
                .thread_names
                .get(&tid)
                .cloned()
                .unwrap_or_else(|| format!("<{}>", tid));

            // Use the leaf function address as a simple key
            // We'll use the combined user+kernel stack as the key
            let stack_key: Vec<u64> = sample
                .sample
                .ustack
                .iter()
                .chain(sample.sample.kstack.iter())
                .copied()
                .collect();

            let mut leaf_symbol = String::new();

            if !stack_key.is_empty() {
                // Determine if the leaf is from kernel or user space
                let has_ustack = !sample.sample.ustack.is_empty();
                let leaf_addr = *stack_key.first().unwrap();

                // Resolve the leaf symbol
                let stack_name = self.resolve_symbol(leaf_addr, pid, !has_ustack);
                leaf_symbol.clone_from(&stack_name);

                self.function_counts
                    .entry(stack_key)
                    .and_modify(|(_, c)| *c += count)
                    .or_insert((stack_name, count));
            }

            // Update per-process detail data for drill-down
            let detail = self.process_detail.entry(pid).or_insert_with(|| {
                ProcessDetailData {
                    pid,
                    name: process_name.clone(),
                    total_samples: 0,
                    sparkline: SparklineData::default(),
                    threads: HashMap::new(),
                }
            });
            detail.total_samples += count;
            detail.sparkline.record(collected_at, count);

            let td = detail.threads.entry(tid).or_insert_with(|| ThreadData {
                tid,
                thread_name: thread_name.clone(),
                sample_count: 0,
                sparkline: SparklineData::default(),
                function_counts: HashMap::new(),
                function_sparklines: HashMap::new(),
            });
            td.sample_count += count;
            td.sparkline.record(collected_at, count);

            if !leaf_symbol.is_empty() {
                *td.function_counts.entry(leaf_symbol.clone()).or_insert(0) += count;
                td.function_sparklines
                    .entry(leaf_symbol)
                    .or_insert_with(SparklineData::default)
                    .record(collected_at, count);
            }
        }

        self.stats
            .unique_stacks
            .store(self.function_counts.len() as u64, Ordering::Relaxed);
        self.stats
            .processes_seen
            .store(self.process_counts.len() as u64, Ordering::Relaxed);
    }

    fn finish(
        &self,
    ) -> (
        AggregatedProfile,
        &HashMap<Pid, ProcessInfo>,
        &HashMap<ExecutableId, ObjectFileInfo>,
    ) {
        (AggregatedProfile::new(), &self.procs, &self.objs)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// TUI Application state
pub struct App {
    pub collector: ThreadSafeCollector,
    #[allow(dead_code)]
    stats: Arc<LiveStats>,
    pub should_stop: Arc<AtomicBool>,
    pub start_time: Instant,
    pub functions_scroll: usize,
    pub processes_scroll: usize,
    pub focus: Focus,
    pub sample_freq: u64,
    pub view_mode: ViewMode,
    pub detail_scroll: usize,
    pub processes_selected: usize,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Focus {
    Functions,
    Processes,
}

impl App {
    pub fn new(
        collector: ThreadSafeCollector,
        stats: Arc<LiveStats>,
        should_stop: Arc<AtomicBool>,
        sample_freq: u64,
    ) -> Self {
        Self {
            collector,
            stats,
            should_stop,
            start_time: Instant::now(),
            functions_scroll: 0,
            processes_scroll: 0,
            focus: Focus::Functions,
            sample_freq,
            view_mode: ViewMode::Overview,
            detail_scroll: 0,
            processes_selected: 0,
        }
    }

    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Functions => Focus::Processes,
            Focus::Processes => Focus::Functions,
        };
    }

    pub fn scroll_up(&mut self) {
        match self.view_mode {
            ViewMode::ProcessDetail { .. } => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
            }
            ViewMode::Overview => match self.focus {
                Focus::Functions => {
                    self.functions_scroll = self.functions_scroll.saturating_sub(1);
                }
                Focus::Processes => {
                    self.processes_selected = self.processes_selected.saturating_sub(1);
                    self.processes_scroll = self.processes_scroll.saturating_sub(1);
                }
            },
        }
    }

    pub fn scroll_down(&mut self) {
        match self.view_mode {
            ViewMode::ProcessDetail { .. } => {
                self.detail_scroll = self.detail_scroll.saturating_add(1);
            }
            ViewMode::Overview => match self.focus {
                Focus::Functions => {
                    self.functions_scroll = self.functions_scroll.saturating_add(1);
                }
                Focus::Processes => {
                    self.processes_selected = self.processes_selected.saturating_add(1);
                    self.processes_scroll = self.processes_scroll.saturating_add(1);
                }
            },
        }
    }
}

/// Initialize the terminal for TUI
pub fn init_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(io::stdout()))
}

/// Restore terminal to normal state
pub fn restore_terminal() -> io::Result<()> {
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

/// Main TUI event loop
pub fn run_tui(app: &mut App) -> io::Result<()> {
    let mut terminal = init_terminal()?;

    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui(f, app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => {
                            app.should_stop.store(true, Ordering::Relaxed);
                            break;
                        }
                        KeyCode::Esc => match &app.view_mode {
                            ViewMode::Overview => {
                                app.should_stop.store(true, Ordering::Relaxed);
                                break;
                            }
                            ViewMode::ProcessDetail { .. } => {
                                app.view_mode = ViewMode::Overview;
                            }
                        },
                        KeyCode::Enter => {
                            if app.view_mode == ViewMode::Overview
                                && app.focus == Focus::Processes
                            {
                                let collector = app.collector.lock().unwrap();
                                if let Some(lc) =
                                    collector.as_any().downcast_ref::<LiveCollector>()
                                {
                                    let processes = lc.get_top_processes(200);
                                    if let Some(entry) =
                                        processes.get(app.processes_selected)
                                    {
                                        app.view_mode = ViewMode::ProcessDetail {
                                            pid: entry.pid,
                                            group_by: GroupBy::ThreadName,
                                        };
                                        app.detail_scroll = 0;
                                    }
                                }
                                drop(collector);
                            }
                        }
                        KeyCode::Char('g') => {
                            if let ViewMode::ProcessDetail {
                                ref mut group_by, ..
                            } = app.view_mode
                            {
                                *group_by = group_by.next();
                                app.detail_scroll = 0;
                            }
                        }
                        KeyCode::Tab => {
                            if app.view_mode == ViewMode::Overview {
                                app.toggle_focus();
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                        KeyCode::PageUp => {
                            for _ in 0..10 {
                                app.scroll_up();
                            }
                        }
                        KeyCode::PageDown => {
                            for _ in 0..10 {
                                app.scroll_down();
                            }
                        }
                        KeyCode::Home => match &app.view_mode {
                            ViewMode::ProcessDetail { .. } => app.detail_scroll = 0,
                            ViewMode::Overview => match app.focus {
                                Focus::Functions => app.functions_scroll = 0,
                                Focus::Processes => {
                                    app.processes_scroll = 0;
                                    app.processes_selected = 0;
                                }
                            },
                        },
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }

        if app.should_stop.load(Ordering::Relaxed) {
            break;
        }
    }

    restore_terminal()?;
    Ok(())
}

/// Render the UI
fn ui(f: &mut Frame, app: &App) {
    let area = f.area();

    // Main layout: header, content, footer
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(3), // Stats bar
            Constraint::Min(10),   // Content
            Constraint::Length(1), // Footer
        ])
        .split(area);

    render_header(f, main_layout[0], app);
    render_stats_bar(f, main_layout[1], app);

    match &app.view_mode {
        ViewMode::Overview => {
            render_content(f, main_layout[2], app);
        }
        ViewMode::ProcessDetail { pid, group_by } => {
            render_process_detail(f, main_layout[2], app, *pid, *group_by);
        }
    }

    render_footer(f, main_layout[3], app);
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let elapsed = app.start_time.elapsed();
    let elapsed_str = format!(
        "{:02}:{:02}:{:02}",
        elapsed.as_secs() / 3600,
        (elapsed.as_secs() % 3600) / 60,
        elapsed.as_secs() % 60
    );

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " LIGHTSWITCH ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{}Hz", app.sample_freq),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("  "),
        Span::styled(
            elapsed_str,
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title_alignment(Alignment::Center),
    );

    f.render_widget(header, area);
}

fn render_stats_bar(f: &mut Frame, area: Rect, app: &App) {
    let collector = app.collector.lock().unwrap();
    let live_collector = collector.as_any().downcast_ref::<LiveCollector>();

    let (samples_per_sec, total_samples, unique_stacks, processes) =
        if let Some(lc) = live_collector {
            (
                lc.samples_per_second(),
                lc.stats.total_samples.load(Ordering::Relaxed),
                lc.stats.unique_stacks.load(Ordering::Relaxed),
                lc.stats.processes_seen.load(Ordering::Relaxed),
            )
        } else {
            (0.0, 0, 0, 0)
        };
    drop(collector);

    let stats_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    let stat_style = Style::default().fg(Color::White);
    let value_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);

    let stats = [
        ("Samples/s", format!("{:.1}", samples_per_sec)),
        ("Total", format!("{}", total_samples)),
        ("Stacks", format!("{}", unique_stacks)),
        ("Procs", format!("{}", processes)),
    ];

    for (i, (label, value)) in stats.iter().enumerate() {
        let widget = Paragraph::new(Line::from(vec![
            Span::styled(format!("{}: ", label), stat_style),
            Span::styled(value.clone(), value_style),
        ]))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        f.render_widget(widget, stats_layout[i]);
    }
}

fn render_content(f: &mut Frame, area: Rect, app: &App) {
    let content_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    render_functions_table(f, content_layout[0], app);
    render_processes_table(f, content_layout[1], app);
}

fn render_functions_table(f: &mut Frame, area: Rect, app: &App) {
    let is_focused = app.focus == Focus::Functions;
    let border_color = if is_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let collector = app.collector.lock().unwrap();
    let functions = if let Some(lc) = collector.as_any().downcast_ref::<LiveCollector>() {
        lc.get_top_functions(500)
    } else {
        vec![]
    };
    drop(collector);

    let header = Row::new(vec![
        Cell::from("Samples").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("%").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Address / Function").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().fg(Color::Yellow))
    .height(1);

    let visible_height = area.height.saturating_sub(4) as usize;
    let scroll = app
        .functions_scroll
        .min(functions.len().saturating_sub(visible_height));

    let rows: Vec<Row> = functions
        .iter()
        .skip(scroll)
        .take(visible_height)
        .enumerate()
        .map(|(i, entry)| {
            let style = if i % 2 == 0 {
                Style::default()
            } else {
                Style::default().bg(Color::Rgb(30, 30, 40))
            };

            let bar_width = (entry.percentage / 100.0 * 10.0) as usize;
            let bar = "".repeat(bar_width.min(10));

            Row::new(vec![
                Cell::from(format!("{:>8}", entry.count)),
                Cell::from(format!("{:>5.1}% {}", entry.percentage, bar))
                    .style(Style::default().fg(color_for_percentage(entry.percentage))),
                Cell::from(truncate_string(&entry.name, 40)),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(18),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(" Top Stacks ({}) ", functions.len()))
            .title_style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(table, area);

    // Render scrollbar
    if functions.len() > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some(""))
            .end_symbol(Some(""));
        let mut scrollbar_state = ScrollbarState::new(functions.len()).position(scroll);
        f.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

fn render_processes_table(f: &mut Frame, area: Rect, app: &App) {
    let is_focused = app.focus == Focus::Processes;
    let border_color = if is_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let collector = app.collector.lock().unwrap();
    let processes = if let Some(lc) = collector.as_any().downcast_ref::<LiveCollector>() {
        lc.get_top_processes(200)
    } else {
        vec![]
    };
    drop(collector);

    let header = Row::new(vec![
        Cell::from("PID").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Samples").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("%").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Command").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().fg(Color::Yellow))
    .height(1);

    let visible_height = area.height.saturating_sub(4) as usize;
    let scroll = app
        .processes_scroll
        .min(processes.len().saturating_sub(visible_height));

    let selected_in_view = app.processes_selected.saturating_sub(scroll);

    let rows: Vec<Row> = processes
        .iter()
        .skip(scroll)
        .take(visible_height)
        .enumerate()
        .map(|(i, entry)| {
            let is_selected = is_focused && i == selected_in_view;
            let style = if is_selected {
                Style::default()
                    .bg(Color::Rgb(50, 50, 80))
                    .add_modifier(Modifier::BOLD)
            } else if i % 2 == 0 {
                Style::default()
            } else {
                Style::default().bg(Color::Rgb(30, 30, 40))
            };

            let marker = if is_selected { "\u{25b6} " } else { "  " };

            Row::new(vec![
                Cell::from(format!("{}{:>7}", marker, entry.pid)),
                Cell::from(format!("{:>8}", entry.count)),
                Cell::from(format!("{:>5.1}%", entry.percentage))
                    .style(Style::default().fg(color_for_percentage(entry.percentage))),
                Cell::from(truncate_string(&entry.name, 20)),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(" Processes ({}) ", processes.len()))
            .title_style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(table, area);

    // Render scrollbar
    if processes.len() > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some(""))
            .end_symbol(Some(""));
        let mut scrollbar_state = ScrollbarState::new(processes.len()).position(scroll);
        f.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

fn render_process_detail(f: &mut Frame, area: Rect, app: &App, pid: Pid, group_by: GroupBy) {
    let collector = app.collector.lock().unwrap();
    let (summary, entries) = if let Some(lc) = collector.as_any().downcast_ref::<LiveCollector>() {
        let summary = lc.get_process_summary(pid);
        let entries = lc.get_process_detail(pid, group_by, 500);
        (summary, entries)
    } else {
        (None, vec![])
    };
    drop(collector);

    let detail_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Process summary
            Constraint::Min(5),   // Grouped table
        ])
        .split(area);

    // Render process summary bar
    if let Some((name, total, sparkline)) = summary {
        let spark_str = sparkline.render(30);
        let summary_widget = Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" PID {} ", pid),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                name,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  {} samples  ", total)),
            Span::styled(spark_str, Style::default().fg(Color::Green)),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(format!(" Process Detail [{}] ", group_by.label()))
                .title_style(
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
        );
        f.render_widget(summary_widget, detail_layout[0]);
    } else {
        let empty = Paragraph::new(format!(" No data for PID {} ", pid)).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(empty, detail_layout[0]);
    }

    // Render grouped table with sparklines
    let sparkline_width: usize = 20;

    let header = Row::new(vec![
        Cell::from(group_by.label()).style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Samples").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("%").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Activity").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().fg(Color::Yellow))
    .height(1);

    let visible_height = detail_layout[1].height.saturating_sub(4) as usize;
    let scroll = app
        .detail_scroll
        .min(entries.len().saturating_sub(visible_height));

    let rows: Vec<Row> = entries
        .iter()
        .skip(scroll)
        .take(visible_height)
        .enumerate()
        .map(|(i, entry)| {
            let style = if i % 2 == 0 {
                Style::default()
            } else {
                Style::default().bg(Color::Rgb(30, 30, 40))
            };

            Row::new(vec![
                Cell::from(truncate_string(&entry.key, 30)),
                Cell::from(format!("{:>8}", entry.count)),
                Cell::from(format!("{:>5.1}%", entry.percentage))
                    .style(Style::default().fg(color_for_percentage(entry.percentage))),
                Cell::from(entry.sparkline.render(sparkline_width))
                    .style(Style::default().fg(Color::Green)),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(20),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(sparkline_width as u16 + 2),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(
                " Grouped by {} ({}) ",
                group_by.label(),
                entries.len()
            ))
            .title_style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );

    f.render_widget(table, detail_layout[1]);

    // Scrollbar
    if entries.len() > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("\u{25b2}"))
            .end_symbol(Some("\u{25bc}"));
        let mut scrollbar_state = ScrollbarState::new(entries.len()).position(scroll);
        f.render_stateful_widget(
            scrollbar,
            detail_layout[1].inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let keys: Vec<(&str, &str)> = match &app.view_mode {
        ViewMode::Overview => vec![
            ("q", "Quit"),
            ("Tab", "Switch panel"),
            ("Enter", "Drill down"),
            ("\u{2191}\u{2193}", "Scroll"),
            ("PgUp/Dn", "Page"),
        ],
        ViewMode::ProcessDetail { .. } => vec![
            ("q", "Quit"),
            ("Esc", "Back"),
            ("g", "Cycle group"),
            ("\u{2191}\u{2193}", "Scroll"),
            ("PgUp/Dn", "Page"),
        ],
    };

    let spans: Vec<Span> = keys
        .iter()
        .flat_map(|(key, desc)| {
            vec![
                Span::styled(
                    format!(" {} ", key),
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" {}  ", desc), Style::default().fg(Color::Gray)),
            ]
        })
        .collect();

    let footer = Paragraph::new(Line::from(spans));
    f.render_widget(footer, area);
}

fn color_for_percentage(pct: f64) -> Color {
    if pct >= 50.0 {
        Color::Red
    } else if pct >= 20.0 {
        Color::Yellow
    } else if pct >= 10.0 {
        Color::Green
    } else {
        Color::Cyan
    }
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
