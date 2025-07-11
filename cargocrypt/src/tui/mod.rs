//! # CargoCrypt TUI - Beautiful Terminal Interface
//!
//! A cargo-themed TUI dashboard for managing secrets, repositories, and security scanning.
//! Features vim-like navigation, real-time updates, and beautiful animations.

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Tabs, Wrap,
    },
    Frame, Terminal,
};
use std::{
    collections::HashMap,
    io::{self, Stdout},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

use crate::{
    detection::{Finding, SecretDetector},
    CargoCrypt, CryptoResult,
};

mod app;
mod clipboard;
mod dashboard;
mod events;
mod notifications;
mod secrets;
mod security;
mod styles;
mod widgets;

pub use app::*;
pub use clipboard::*;
pub use dashboard::*;
pub use events::*;
pub use notifications::*;
pub use secrets::*;
pub use security::*;
pub use styles::*;
pub use widgets::*;

/// Main TUI application state
#[derive(Debug, Clone)]
pub struct TuiApp {
    /// Current active tab
    pub current_tab: usize,
    /// Navigation state
    pub nav_state: NavigationState,
    /// Dashboard data
    pub dashboard: Dashboard,
    /// Secret management
    pub secrets: SecretManager,
    /// Security scanner
    pub security: SecurityManager,
    /// Clipboard manager
    pub clipboard: ClipboardManager,
    /// Notification system
    pub notifications: NotificationManager,
    /// Performance metrics
    pub metrics: PerformanceMetrics,
    /// Animation state
    pub animation: AnimationState,
    /// Vim-like command mode
    pub command_mode: CommandMode,
    /// Input buffer for commands
    pub input_buffer: String,
    /// Should quit the application
    pub should_quit: bool,
}

/// Navigation state for vim-like controls
#[derive(Debug, Clone)]
pub struct NavigationState {
    pub mode: NavigationMode,
    pub selected_item: usize,
    pub scroll_offset: usize,
    pub list_state: ListState,
    pub scrollbar_state: ScrollbarState,
}

/// Navigation modes
#[derive(Debug, Clone, PartialEq)]
pub enum NavigationMode {
    Normal,
    Insert,
    Visual,
    Command,
}

/// Command mode for vim-like operations
#[derive(Debug, Clone)]
pub struct CommandMode {
    pub active: bool,
    pub input: String,
    pub history: Vec<String>,
    pub history_index: usize,
}

/// Animation state for cargo-themed effects
#[derive(Debug, Clone)]
pub struct AnimationState {
    pub frame: usize,
    pub last_update: Instant,
    pub spinning_cargo: usize,
    pub security_scan_progress: f64,
    pub pulse_phase: f64,
}

/// Performance metrics for the TUI
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub fps: f64,
    pub frame_time: Duration,
    pub memory_usage: u64,
    pub cpu_usage: f64,
    pub active_secrets: usize,
    pub scan_results: usize,
}

/// Tab definitions for the main interface
#[derive(Debug, Clone, Copy)]
pub enum Tab {
    Dashboard = 0,
    Secrets = 1,
    Security = 2,
    Repository = 3,
    Settings = 4,
}

impl Tab {
    pub fn titles() -> Vec<&'static str> {
        vec!["🏠 Dashboard", "🔐 Secrets", "🛡️ Security", "📦 Repository", "⚙️ Settings"]
    }
    
    pub fn from_index(index: usize) -> Option<Tab> {
        match index {
            0 => Some(Tab::Dashboard),
            1 => Some(Tab::Secrets),
            2 => Some(Tab::Security),
            3 => Some(Tab::Repository),
            4 => Some(Tab::Settings),
            _ => None,
        }
    }
}

impl Default for TuiApp {
    fn default() -> Self {
        Self {
            current_tab: 0,
            nav_state: NavigationState {
                mode: NavigationMode::Normal,
                selected_item: 0,
                scroll_offset: 0,
                list_state: ListState::default(),
                scrollbar_state: ScrollbarState::default(),
            },
            dashboard: Dashboard::default(),
            secrets: SecretManager::default(),
            security: SecurityManager::default(),
            clipboard: ClipboardManager::default(),
            notifications: NotificationManager::default(),
            metrics: PerformanceMetrics {
                fps: 60.0,
                frame_time: Duration::from_millis(16),
                memory_usage: 0,
                cpu_usage: 0.0,
                active_secrets: 0,
                scan_results: 0,
            },
            animation: AnimationState {
                frame: 0,
                last_update: Instant::now(),
                spinning_cargo: 0,
                security_scan_progress: 0.0,
                pulse_phase: 0.0,
            },
            command_mode: CommandMode {
                active: false,
                input: String::new(),
                history: Vec::new(),
                history_index: 0,
            },
            input_buffer: String::new(),
            should_quit: false,
        }
    }
}

impl TuiApp {
    /// Create a new TUI application
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize the TUI with CargoCrypt backend
    pub async fn init(&mut self, crypt: Arc<CargoCrypt>) -> CryptoResult<()> {
        // Initialize all components
        self.dashboard.init(crypt.clone()).await?;
        self.secrets.init(crypt.clone()).await?;
        self.security.init(crypt.clone()).await?;
        
        // Set up clipboard auto-clear
        self.clipboard.set_auto_clear(Duration::from_secs(30));
        
        // Initialize metrics
        self.update_metrics().await?;
        
        Ok(())
    }

    /// Update application state
    pub async fn update(&mut self) -> CryptoResult<()> {
        let now = Instant::now();
        
        // Update animations
        if now.duration_since(self.animation.last_update) > Duration::from_millis(50) {
            self.animation.frame = (self.animation.frame + 1) % 8;
            self.animation.spinning_cargo = (self.animation.spinning_cargo + 1) % 4;
            self.animation.pulse_phase = (self.animation.pulse_phase + 0.1) % (2.0 * std::f64::consts::PI);
            self.animation.last_update = now;
        }
        
        // Update dashboard
        self.dashboard.update().await?;
        
        // Update security scan progress
        if self.security.is_scanning() {
            self.animation.security_scan_progress = self.security.scan_progress();
        }
        
        // Update metrics
        self.update_metrics().await?;
        
        // Process clipboard auto-clear
        self.clipboard.update();
        
        // Process notifications
        self.notifications.update();
        
        Ok(())
    }

    /// Update performance metrics
    async fn update_metrics(&mut self) -> CryptoResult<()> {
        self.metrics.active_secrets = self.secrets.count().await;
        self.metrics.scan_results = self.security.findings_count().await;
        
        // Update FPS calculation
        let frame_time = Instant::now().duration_since(self.animation.last_update);
        self.metrics.frame_time = frame_time;
        self.metrics.fps = 1.0 / frame_time.as_secs_f64();
        
        Ok(())
    }

    /// Handle input events
    pub async fn handle_input(&mut self, event: Event) -> CryptoResult<()> {
        match event {
            Event::Key(key) => {
                if self.command_mode.active {
                    self.handle_command_mode_input(key).await?;
                } else {
                    self.handle_normal_mode_input(key).await?;
                }
            }
            Event::Mouse(_) => {
                // Handle mouse events if needed
            }
            Event::Resize(_, _) => {
                // Handle terminal resize
            }
            _ => {}
        }
        
        Ok(())
    }

    /// Handle normal mode input (vim-like)
    async fn handle_normal_mode_input(&mut self, key: crossterm::event::KeyEvent) -> CryptoResult<()> {
        match key.code {
            // Navigation
            KeyCode::Char('h') | KeyCode::Left => self.nav_left(),
            KeyCode::Char('l') | KeyCode::Right => self.nav_right(),
            KeyCode::Char('j') | KeyCode::Down => self.nav_down(),
            KeyCode::Char('k') | KeyCode::Up => self.nav_up(),
            KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::NONE) => self.nav_top(),
            KeyCode::Char('G') => self.nav_bottom(),
            
            // Tab switching
            KeyCode::Char('1') => self.switch_tab(0),
            KeyCode::Char('2') => self.switch_tab(1),
            KeyCode::Char('3') => self.switch_tab(2),
            KeyCode::Char('4') => self.switch_tab(3),
            KeyCode::Char('5') => self.switch_tab(4),
            KeyCode::Tab => self.next_tab(),
            KeyCode::BackTab => self.prev_tab(),
            
            // Actions
            KeyCode::Enter => self.activate_selected().await?,
            KeyCode::Char(' ') => self.toggle_selected().await?,
            KeyCode::Char('r') => self.refresh().await?,
            KeyCode::Char('s') => self.start_security_scan().await?,
            KeyCode::Char('c') => self.copy_to_clipboard().await?,
            
            // Command mode
            KeyCode::Char(':') => self.enter_command_mode(),
            KeyCode::Char('/') => self.enter_search_mode(),
            
            // Quit
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => self.should_quit = true,
            KeyCode::Esc => self.cancel_current_action(),
            
            _ => {}
        }
        
        Ok(())
    }

    /// Handle command mode input
    async fn handle_command_mode_input(&mut self, key: crossterm::event::KeyEvent) -> CryptoResult<()> {
        match key.code {
            KeyCode::Enter => {
                self.execute_command().await?;
                self.exit_command_mode();
            }
            KeyCode::Esc => self.exit_command_mode(),
            KeyCode::Backspace => {
                self.command_mode.input.pop();
            }
            KeyCode::Char(c) => {
                self.command_mode.input.push(c);
            }
            _ => {}
        }
        
        Ok(())
    }

    /// Navigation helpers
    fn nav_left(&mut self) {
        if self.nav_state.selected_item > 0 {
            self.nav_state.selected_item -= 1;
        }
    }

    fn nav_right(&mut self) {
        self.nav_state.selected_item += 1;
    }

    fn nav_down(&mut self) {
        self.nav_state.selected_item += 1;
        self.nav_state.list_state.select(Some(self.nav_state.selected_item));
    }

    fn nav_up(&mut self) {
        if self.nav_state.selected_item > 0 {
            self.nav_state.selected_item -= 1;
            self.nav_state.list_state.select(Some(self.nav_state.selected_item));
        }
    }

    fn nav_top(&mut self) {
        self.nav_state.selected_item = 0;
        self.nav_state.list_state.select(Some(0));
    }

    fn nav_bottom(&mut self) {
        // Implementation depends on current view
    }

    /// Tab management
    fn switch_tab(&mut self, tab: usize) {
        if tab < Tab::titles().len() {
            self.current_tab = tab;
            self.nav_state.selected_item = 0;
            self.nav_state.list_state.select(Some(0));
        }
    }

    fn next_tab(&mut self) {
        self.current_tab = (self.current_tab + 1) % Tab::titles().len();
    }

    fn prev_tab(&mut self) {
        self.current_tab = if self.current_tab == 0 {
            Tab::titles().len() - 1
        } else {
            self.current_tab - 1
        };
    }

    /// Command mode
    fn enter_command_mode(&mut self) {
        self.command_mode.active = true;
        self.command_mode.input.clear();
    }

    fn enter_search_mode(&mut self) {
        self.command_mode.active = true;
        self.command_mode.input = "/".to_string();
    }

    fn exit_command_mode(&mut self) {
        self.command_mode.active = false;
        if !self.command_mode.input.is_empty() {
            self.command_mode.history.push(self.command_mode.input.clone());
        }
        self.command_mode.input.clear();
    }

    /// Execute vim-like commands
    async fn execute_command(&mut self) -> CryptoResult<()> {
        let command = self.command_mode.input.trim();
        
        match command {
            "q" | "quit" => self.should_quit = true,
            "w" | "write" => self.save_current().await?,
            "wq" => {
                self.save_current().await?;
                self.should_quit = true;
            }
            "refresh" | "r" => self.refresh().await?,
            "scan" => self.start_security_scan().await?,
            "clear" => self.clear_clipboard(),
            cmd if cmd.starts_with("search ") => {
                let query = &cmd[7..];
                self.search(query).await?;
            }
            cmd if cmd.starts_with("/") => {
                let query = &cmd[1..];
                self.search(query).await?;
            }
            _ => {
                self.notifications.add_warning(&format!("Unknown command: {}", command));
            }
        }
        
        Ok(())
    }

    /// Action implementations
    async fn activate_selected(&mut self) -> CryptoResult<()> {
        match Tab::from_index(self.current_tab) {
            Some(Tab::Secrets) => {
                self.secrets.activate_selected(self.nav_state.selected_item).await?;
            }
            Some(Tab::Security) => {
                self.security.activate_selected(self.nav_state.selected_item).await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn toggle_selected(&mut self) -> CryptoResult<()> {
        match Tab::from_index(self.current_tab) {
            Some(Tab::Secrets) => {
                self.secrets.toggle_selected(self.nav_state.selected_item).await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn refresh(&mut self) -> CryptoResult<()> {
        self.dashboard.refresh().await?;
        self.secrets.refresh().await?;
        self.security.refresh().await?;
        self.notifications.add_info("Refreshed all data");
        Ok(())
    }

    async fn start_security_scan(&mut self) -> CryptoResult<()> {
        self.security.start_scan().await?;
        self.notifications.add_info("Security scan started");
        Ok(())
    }

    async fn copy_to_clipboard(&mut self) -> CryptoResult<()> {
        match Tab::from_index(self.current_tab) {
            Some(Tab::Secrets) => {
                if let Some(secret) = self.secrets.get_selected(self.nav_state.selected_item).await? {
                    self.clipboard.copy_secret(&secret).await?;
                    self.notifications.add_success("Secret copied to clipboard (auto-clear in 30s)");
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn search(&mut self, query: &str) -> CryptoResult<()> {
        match Tab::from_index(self.current_tab) {
            Some(Tab::Secrets) => {
                self.secrets.search(query).await?;
            }
            Some(Tab::Security) => {
                self.security.search(query).await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn save_current(&mut self) -> CryptoResult<()> {
        match Tab::from_index(self.current_tab) {
            Some(Tab::Secrets) => {
                self.secrets.save().await?;
                self.notifications.add_success("Secrets saved");
            }
            _ => {}
        }
        Ok(())
    }

    fn clear_clipboard(&mut self) {
        self.clipboard.clear();
        self.notifications.add_info("Clipboard cleared");
    }

    fn cancel_current_action(&mut self) {
        self.command_mode.active = false;
        self.command_mode.input.clear();
    }

    /// Render the TUI
    pub fn render<B: Backend>(&mut self, f: &mut Frame<B>) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Content
                Constraint::Length(3), // Footer
            ])
            .split(f.size());

        self.render_header(f, chunks[0]);
        self.render_content(f, chunks[1]);
        self.render_footer(f, chunks[2]);
    }

    /// Render header with tabs
    fn render_header<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let titles = Tab::titles();
        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::ALL).title("CargoCrypt"))
            .style(CargoStyle::default())
            .highlight_style(CargoStyle::selected())
            .select(self.current_tab);
        
        f.render_widget(tabs, area);
    }

    /// Render main content area
    fn render_content<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        match Tab::from_index(self.current_tab) {
            Some(Tab::Dashboard) => self.dashboard.render(f, area, &self.animation),
            Some(Tab::Secrets) => self.secrets.render(f, area, &self.nav_state),
            Some(Tab::Security) => self.security.render(f, area, &self.nav_state, &self.animation),
            Some(Tab::Repository) => self.render_repository_tab(f, area),
            Some(Tab::Settings) => self.render_settings_tab(f, area),
            None => {}
        }
    }

    /// Render footer with status and commands
    fn render_footer<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(0),     // Status
                Constraint::Length(20), // Metrics
            ])
            .split(area);

        // Status line
        let status_text = if self.command_mode.active {
            format!(":{}", self.command_mode.input)
        } else {
            format!("Mode: {} | {} | Press ':' for commands, 'q' to quit", 
                match self.nav_state.mode {
                    NavigationMode::Normal => "NORMAL",
                    NavigationMode::Insert => "INSERT",
                    NavigationMode::Visual => "VISUAL",
                    NavigationMode::Command => "COMMAND",
                },
                match Tab::from_index(self.current_tab) {
                    Some(Tab::Dashboard) => "hjkl:navigate r:refresh",
                    Some(Tab::Secrets) => "hjkl:navigate Space:toggle c:copy",
                    Some(Tab::Security) => "hjkl:navigate s:scan Enter:details",
                    Some(Tab::Repository) => "hjkl:navigate r:refresh",
                    Some(Tab::Settings) => "hjkl:navigate Enter:edit",
                    None => "hjkl:navigate",
                }
            )
        };

        let status = Paragraph::new(status_text)
            .style(CargoStyle::default())
            .block(Block::default().borders(Borders::ALL));
        
        f.render_widget(status, chunks[0]);

        // Metrics
        let metrics_text = format!(
            "FPS: {:.1} | Secrets: {} | Findings: {}",
            self.metrics.fps,
            self.metrics.active_secrets,
            self.metrics.scan_results
        );
        
        let metrics = Paragraph::new(metrics_text)
            .style(CargoStyle::default())
            .block(Block::default().borders(Borders::ALL));
        
        f.render_widget(metrics, chunks[1]);

        // Render notifications overlay
        self.notifications.render(f, f.size());
    }

    /// Render repository tab
    fn render_repository_tab<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let repo_info = Paragraph::new("Repository information will be displayed here")
            .style(CargoStyle::default())
            .block(Block::default().borders(Borders::ALL).title("Repository"));
        
        f.render_widget(repo_info, area);
    }

    /// Render settings tab
    fn render_settings_tab<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let settings_info = Paragraph::new("Settings will be displayed here")
            .style(CargoStyle::default())
            .block(Block::default().borders(Borders::ALL).title("Settings"));
        
        f.render_widget(settings_info, area);
    }
}

/// Run the TUI application
pub async fn run_tui(crypt: Arc<CargoCrypt>) -> CryptoResult<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = TuiApp::new();
    app.init(crypt).await?;

    // Event handling
    let (tx, mut rx) = mpsc::unbounded_channel();
    let event_tx = tx.clone();
    
    // Spawn event handler
    tokio::spawn(async move {
        loop {
            if let Ok(event) = event::read() {
                if event_tx.send(event).is_err() {
                    break;
                }
            }
        }
    });

    // Main loop
    loop {
        terminal.draw(|f| app.render(f))?;
        
        // Handle events
        tokio::select! {
            Some(event) = rx.recv() => {
                app.handle_input(event).await?;
            }
            _ = tokio::time::sleep(Duration::from_millis(16)) => {
                app.update().await?;
            }
        }
        
        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}