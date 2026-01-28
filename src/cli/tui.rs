use std::collections::HashMap;
use std::io::{self, Stdout};
use std::path::PathBuf;
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
            *self.process_counts.entry(pid).or_insert(0) += count;

            // Try to get process name from /proc
            if let std::collections::hash_map::Entry::Vacant(e) = self.process_names.entry(pid) {
                if let Ok(name) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
                    e.insert(name.trim().to_string());
                }
            }

            // Use the leaf function address as a simple key
            // We'll use the combined user+kernel stack as the key
            let stack_key: Vec<u64> = sample
                .sample
                .ustack
                .iter()
                .chain(sample.sample.kstack.iter())
                .copied()
                .collect();

            if !stack_key.is_empty() {
                // Determine if the leaf is from kernel or user space
                let has_ustack = !sample.sample.ustack.is_empty();
                let leaf_addr = *stack_key.first().unwrap();

                // Resolve the leaf symbol
                let stack_name = self.resolve_symbol(leaf_addr, pid, !has_ustack);

                self.function_counts
                    .entry(stack_key)
                    .and_modify(|(_, c)| *c += count)
                    .or_insert((stack_name, count));
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
        }
    }

    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Functions => Focus::Processes,
            Focus::Processes => Focus::Functions,
        };
    }

    pub fn scroll_up(&mut self) {
        match self.focus {
            Focus::Functions => {
                self.functions_scroll = self.functions_scroll.saturating_sub(1);
            }
            Focus::Processes => {
                self.processes_scroll = self.processes_scroll.saturating_sub(1);
            }
        }
    }

    pub fn scroll_down(&mut self) {
        match self.focus {
            Focus::Functions => {
                self.functions_scroll = self.functions_scroll.saturating_add(1);
            }
            Focus::Processes => {
                self.processes_scroll = self.processes_scroll.saturating_add(1);
            }
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
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.should_stop.store(true, Ordering::Relaxed);
                            break;
                        }
                        KeyCode::Tab => app.toggle_focus(),
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
                        KeyCode::Home => match app.focus {
                            Focus::Functions => app.functions_scroll = 0,
                            Focus::Processes => app.processes_scroll = 0,
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
    render_content(f, main_layout[2], app);
    render_footer(f, main_layout[3]);
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

    let rows: Vec<Row> = processes
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
                Cell::from(format!("{:>7}", entry.pid)),
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

fn render_footer(f: &mut Frame, area: Rect) {
    let keys = [
        ("q", "Quit"),
        ("Tab", "Switch panel"),
        ("", "Scroll"),
        ("PgUp/Dn", "Page"),
    ];

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
