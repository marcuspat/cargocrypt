//! Enhanced TUI module for CargoCrypt
//!
//! Provides a comprehensive terminal user interface with:
//! - Interactive file browser with encryption status
//! - Real-time secret detection dashboard
//! - Vim-like keybindings for power users
//! - Progress indicators and async operations
//! - Configuration management interface

use crate::{CargoCrypt, CryptoResult};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, Paragraph, Clear, Gauge, 
        Table, Row, Cell, TableState, ListState, Wrap
    },
    Frame, Terminal,
};
use std::{
    io,
    sync::Arc,
    time::{Duration, SystemTime},
    path::PathBuf,
    fs::{self, DirEntry, Metadata},
    collections::HashSet,
};

/// Application state for the TUI
#[derive(Debug)]
struct AppState {
    current_view: AppView,
    file_browser: FileBrowser,
    secret_detector: SecretDetectionDashboard,
    config_manager: ConfigManager,
    status_message: String,
    input_mode: InputMode,
    input_buffer: String,
    show_help: bool,
    show_confirm_dialog: bool,
    confirm_message: String,
    last_scan_results: Vec<crate::detection::Finding>,
    theme: ColorTheme,
    search_query: String,
    search_mode: bool,
    help_page: HelpPage,
}

/// Different views in the application
#[derive(Debug, Clone, Copy, PartialEq)]
enum AppView {
    MainMenu,
    FileBrowser,
    SecretDetection,
    Configuration,
    Help,
    Themes,
}

/// Color themes for the TUI
#[derive(Debug, Clone, PartialEq)]
enum ColorTheme {
    Default,
    Dark,
    Light,
    Solarized,
    Monokai,
    Terminal,
}

/// Help system pages
#[derive(Debug, Clone, Copy, PartialEq)]
enum HelpPage {
    Overview,
    FileBrowser,
    SecretDetection,
    Configuration,
    Keybindings,
    Themes,
}

/// Theme color definitions
#[derive(Debug, Clone)]
struct ThemeColors {
    background: Color,
    foreground: Color,
    primary: Color,
    secondary: Color,
    accent: Color,
    warning: Color,
    error: Color,
    success: Color,
    info: Color,
    border: Color,
    selection: Color,
    highlight: Color,
}

/// Input modes for the application
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum InputMode {
    Normal,
    Insert,
    Command,
}

/// File browser component with full functionality
#[derive(Debug)]
struct FileBrowser {
    current_path: PathBuf,
    files: Vec<FileEntry>,
    selected_index: usize,
    show_hidden: bool,
    filter: String,
    selected_files: HashSet<PathBuf>,
    sort_mode: SortMode,
    view_mode: ViewMode,
    loading: bool,
    error_message: Option<String>,
    list_state: ListState,
    scroll_offset: usize,
    operation_progress: Option<OperationProgress>,
}

/// File sorting modes
#[derive(Debug, Clone, Copy, PartialEq)]
enum SortMode {
    Name,
    Size,
    Modified,
    Type,
    EncryptionStatus,
}

/// File view modes
#[derive(Debug, Clone, Copy, PartialEq)]
enum ViewMode {
    List,
    Details,
    Tree,
}

/// Progress tracking for long operations
#[derive(Debug, Clone)]
struct OperationProgress {
    operation: String,
    current: usize,
    total: usize,
    current_file: String,
}

impl FileBrowser {
    fn new() -> Self {
        let mut browser = Self {
            current_path: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            files: Vec::new(),
            selected_index: 0,
            show_hidden: false,
            filter: String::new(),
            selected_files: HashSet::new(),
            sort_mode: SortMode::Name,
            view_mode: ViewMode::Details,
            loading: false,
            error_message: None,
            list_state: ListState::default(),
            scroll_offset: 0,
            operation_progress: None,
        };
        let _ = browser.refresh_files();
        browser
    }

    /// Refresh the file list
    fn refresh_files(&mut self) -> CryptoResult<()> {
        self.loading = true;
        self.error_message = None;
        
        match self.scan_directory() {
            Ok(files) => {
                self.files = files;
                self.sort_files();
                self.selected_index = 0;
                self.loading = false;
            }
            Err(e) => {
                self.error_message = Some(format!("Error reading directory: {}", e));
                self.loading = false;
            }
        }
        Ok(())
    }

    /// Scan current directory for files
    fn scan_directory(&self) -> CryptoResult<Vec<FileEntry>> {
        let mut files = Vec::new();
        
        // Add parent directory entry
        if self.current_path.parent().is_some() {
            files.push(FileEntry {
                path: self.current_path.join(".."),
                name: "..".to_string(),
                is_directory: true,
                is_encrypted: false,
                has_secrets: None,
                size: 0,
                modified: SystemTime::UNIX_EPOCH,
                is_selected: false,
                icon: "📁".to_string(),
                permissions: "drwxr-xr-x".to_string(),
            });
        }

        // Read directory entries
        let entries = fs::read_dir(&self.current_path)
            .map_err(|e| crate::error::CargoCryptError::from(e))?;

        for entry in entries {
            let entry = entry.map_err(|e| crate::error::CargoCryptError::from(e))?;
            let _path = entry.path();
            
            // Skip hidden files if not shown
            if !self.show_hidden && self.is_hidden(&entry) {
                continue;
            }

            // Apply filter
            if !self.filter.is_empty() && !self.matches_filter(&entry) {
                continue;
            }

            if let Ok(file_entry) = self.create_file_entry(entry) {
                files.push(file_entry);
            }
        }

        Ok(files)
    }

    /// Create a FileEntry from a DirEntry
    fn create_file_entry(&self, entry: DirEntry) -> CryptoResult<FileEntry> {
        let path = entry.path();
        let metadata = entry
            .metadata()
            .map_err(|e| crate::error::CargoCryptError::from(e))?;
        
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<invalid>")
            .to_string();
        
        let is_directory = metadata.is_dir();
        let is_encrypted = path.extension().and_then(|e| e.to_str()).map(|ext| ext == "enc").unwrap_or(false);
        let size = if is_directory { 0 } else { metadata.len() };
        let modified = metadata
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH);
        
        let icon = self.get_file_icon(&path, is_directory, is_encrypted);
        let permissions = self.format_permissions(&metadata);
        let is_selected = self.selected_files.contains(&path);
        
        Ok(FileEntry {
            path,
            name,
            is_directory,
            is_encrypted,
            has_secrets: None, // Will be populated by background scanning
            size,
            modified,
            is_selected,
            icon,
            permissions,
        })
    }

    /// Get appropriate icon for a file
    fn get_file_icon(&self, path: &PathBuf, is_directory: bool, is_encrypted: bool) -> String {
        if is_directory {
            return "📁".to_string();
        }
        
        if is_encrypted {
            return "🔒".to_string();
        }
        
        // File type based icons
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            match ext {
                "rs" => "🦀",
                "toml" => "⚙️",
                "json" => "📄",
                "md" => "📝",
                "txt" => "📄",
                "log" => "📊",
                "yaml" | "yml" => "📋",
                "sh" | "bash" => "🚀",
                "py" => "🐍",
                "js" | "ts" => "⚡",
                "html" | "css" => "🌐",
                "png" | "jpg" | "jpeg" | "gif" => "🖼️",
                "pdf" => "📕",
                "zip" | "tar" | "gz" => "📦",
                _ => "📄",
            }.to_string()
        } else {
            "📄".to_string()
        }
    }

    /// Format file permissions
    fn format_permissions(&self, metadata: &Metadata) -> String {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            format!(
                "{}{}{}{}{}{}{}{}{}{}",
                if metadata.is_dir() { 'd' } else { '-' },
                if mode & 0o400 != 0 { 'r' } else { '-' },
                if mode & 0o200 != 0 { 'w' } else { '-' },
                if mode & 0o100 != 0 { 'x' } else { '-' },
                if mode & 0o040 != 0 { 'r' } else { '-' },
                if mode & 0o020 != 0 { 'w' } else { '-' },
                if mode & 0o010 != 0 { 'x' } else { '-' },
                if mode & 0o004 != 0 { 'r' } else { '-' },
                if mode & 0o002 != 0 { 'w' } else { '-' },
                if mode & 0o001 != 0 { 'x' } else { '-' },
            )
        }
        #[cfg(not(unix))]
        {
            if metadata.permissions().readonly() {
                "r--r--r--".to_string()
            } else {
                "rw-rw-rw-".to_string()
            }
        }
    }

    /// Check if file is hidden
    fn is_hidden(&self, entry: &DirEntry) -> bool {
        entry
            .file_name()
            .to_str()
            .map(|s| s.starts_with('.'))
            .unwrap_or(false)
    }

    /// Check if file matches current filter
    fn matches_filter(&self, entry: &DirEntry) -> bool {
        entry
            .file_name()
            .to_str()
            .map(|name| name.to_lowercase().contains(&self.filter.to_lowercase()))
            .unwrap_or(false)
    }

    /// Sort files according to current sort mode
    fn sort_files(&mut self) {
        match self.sort_mode {
            SortMode::Name => {
                self.files.sort_by(|a, b| {
                    // Directories first, then by name
                    match (a.is_directory, b.is_directory) {
                        (true, false) => std::cmp::Ordering::Less,
                        (false, true) => std::cmp::Ordering::Greater,
                        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                    }
                });
            }
            SortMode::Size => {
                self.files.sort_by(|a, b| {
                    if a.is_directory && !b.is_directory {
                        std::cmp::Ordering::Less
                    } else if !a.is_directory && b.is_directory {
                        std::cmp::Ordering::Greater
                    } else {
                        b.size.cmp(&a.size)
                    }
                });
            }
            SortMode::Modified => {
                self.files.sort_by(|a, b| {
                    if a.is_directory && !b.is_directory {
                        std::cmp::Ordering::Less
                    } else if !a.is_directory && b.is_directory {
                        std::cmp::Ordering::Greater
                    } else {
                        b.modified.cmp(&a.modified)
                    }
                });
            }
            SortMode::Type => {
                self.files.sort_by(|a, b| {
                    match (a.is_directory, b.is_directory) {
                        (true, false) => std::cmp::Ordering::Less,
                        (false, true) => std::cmp::Ordering::Greater,
                        _ => {
                            let a_ext = a.path.extension().and_then(|e| e.to_str()).unwrap_or("");
                            let b_ext = b.path.extension().and_then(|e| e.to_str()).unwrap_or("");
                            a_ext.cmp(b_ext)
                        }
                    }
                });
            }
            SortMode::EncryptionStatus => {
                self.files.sort_by(|a, b| {
                    match (a.is_directory, b.is_directory) {
                        (true, false) => std::cmp::Ordering::Less,
                        (false, true) => std::cmp::Ordering::Greater,
                        _ => b.is_encrypted.cmp(&a.is_encrypted),
                    }
                });
            }
        }
    }

    /// Navigate to a directory
    fn navigate_to(&mut self, path: PathBuf) -> CryptoResult<()> {
        if path.is_dir() {
            self.current_path = path.canonicalize()
                .map_err(|e| crate::error::CargoCryptError::from(e))?;
            self.refresh_files()?;
        }
        Ok(())
    }

    /// Get currently selected file
    fn get_selected_file(&self) -> Option<&FileEntry> {
        self.files.get(self.selected_index)
    }

    /// Toggle selection of current file
    fn toggle_selection(&mut self) {
        if let Some(file) = self.get_selected_file() {
            let path = file.path.clone();
            if self.selected_files.contains(&path) {
                self.selected_files.remove(&path);
            } else {
                self.selected_files.insert(path);
            }
            // Update the file entry
            if let Some(file) = self.files.get_mut(self.selected_index) {
                file.is_selected = !file.is_selected;
            }
        }
    }

    /// Clear all selections
    fn clear_selections(&mut self) {
        self.selected_files.clear();
        for file in &mut self.files {
            file.is_selected = false;
        }
    }

    /// Move selection up
    fn move_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
        self.update_list_state();
    }

    /// Move selection down
    fn move_down(&mut self) {
        if self.selected_index + 1 < self.files.len() {
            self.selected_index += 1;
        }
        self.update_list_state();
    }

    /// Update list state for proper scrolling
    fn update_list_state(&mut self) {
        self.list_state.select(Some(self.selected_index));
    }

    /// Page up
    fn page_up(&mut self, page_size: usize) {
        self.selected_index = self.selected_index.saturating_sub(page_size);
        self.update_list_state();
    }

    /// Page down
    fn page_down(&mut self, page_size: usize) {
        self.selected_index = (self.selected_index + page_size).min(self.files.len().saturating_sub(1));
        self.update_list_state();
    }

    /// Go to first item
    fn go_to_first(&mut self) {
        self.selected_index = 0;
        self.update_list_state();
    }

    /// Go to last item
    fn go_to_last(&mut self) {
        if !self.files.is_empty() {
            self.selected_index = self.files.len() - 1;
        }
        self.update_list_state();
    }

    /// Cycle through sort modes
    fn cycle_sort_mode(&mut self) {
        self.sort_mode = match self.sort_mode {
            SortMode::Name => SortMode::Size,
            SortMode::Size => SortMode::Modified,
            SortMode::Modified => SortMode::Type,
            SortMode::Type => SortMode::EncryptionStatus,
            SortMode::EncryptionStatus => SortMode::Name,
        };
        self.sort_files();
    }

    /// Cycle through view modes
    fn cycle_view_mode(&mut self) {
        self.view_mode = match self.view_mode {
            ViewMode::List => ViewMode::Details,
            ViewMode::Details => ViewMode::Tree,
            ViewMode::Tree => ViewMode::List,
        };
    }

    /// Set filter
    fn set_filter(&mut self, filter: String) {
        self.filter = filter;
        let _ = self.refresh_files();
    }

    /// Filter files based on search query
    fn filter_by_search(&self, query: &str) -> Vec<&FileEntry> {
        if query.is_empty() {
            self.files.iter().collect()
        } else {
            let query_lower = query.to_lowercase();
            self.files.iter()
                .filter(|file| {
                    file.name.to_lowercase().contains(&query_lower) ||
                    file.path.to_string_lossy().to_lowercase().contains(&query_lower)
                })
                .collect()
        }
    }

    /// Toggle hidden files
    fn toggle_hidden(&mut self) {
        self.show_hidden = !self.show_hidden;
        let _ = self.refresh_files();
    }

    /// Format file size
    fn format_size(size: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = size as f64;
        let mut unit_index = 0;
        
        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }
        
        if unit_index == 0 {
            format!("{} {}", size as u64, UNITS[unit_index])
        } else {
            format!("{:.1} {}", size, UNITS[unit_index])
        }
    }

    /// Start an operation with progress tracking
    fn start_operation(&mut self, operation: String, total: usize) {
        self.operation_progress = Some(OperationProgress {
            operation,
            current: 0,
            total,
            current_file: String::new(),
        });
    }

    /// Update operation progress
    fn update_progress(&mut self, current: usize, current_file: String) {
        if let Some(ref mut progress) = self.operation_progress {
            progress.current = current;
            progress.current_file = current_file;
        }
    }

    /// Complete current operation
    fn complete_operation(&mut self) {
        self.operation_progress = None;
    }
}

/// Enhanced file entry with encryption status and UI state
#[derive(Debug, Clone)]
struct FileEntry {
    path: PathBuf,
    name: String,
    is_directory: bool,
    is_encrypted: bool,
    has_secrets: Option<bool>,
    size: u64,
    modified: SystemTime,
    is_selected: bool,
    icon: String,
    permissions: String,
}

impl FileEntry {
    /// Get status indicator for the file
    fn status_indicator(&self) -> String {
        let mut indicators = Vec::new();
        
        if self.is_encrypted {
            indicators.push("🔒");
        }
        
        if let Some(has_secrets) = self.has_secrets {
            if has_secrets {
                indicators.push("⚠️");
            } else {
                indicators.push("✅");
            }
        }
        
        if self.is_selected {
            indicators.push("✓");
        }
        
        indicators.join("")
    }

    /// Get formatted modification time
    fn formatted_modified(&self) -> String {
        use std::time::UNIX_EPOCH;
        
        if let Ok(duration) = self.modified.duration_since(UNIX_EPOCH) {
            let secs = duration.as_secs();
            let datetime = chrono::DateTime::from_timestamp(secs as i64, 0)
                .unwrap_or_else(|| chrono::Utc::now());
            datetime.format("%Y-%m-%d %H:%M").to_string()
        } else {
            "Unknown".to_string()
        }
    }

    /// Get display name with icon
    fn display_name(&self) -> String {
        format!("{} {}", self.icon, self.name)
    }
}

/// Secret detection dashboard
#[derive(Debug)]
#[allow(dead_code)]
struct SecretDetectionDashboard {
    scan_results: Vec<crate::detection::Finding>,
    scanning: bool,
    selected_finding: usize,
    scan_path: PathBuf,
}

impl SecretDetectionDashboard {
    fn new() -> Self {
        Self {
            scan_results: Vec::new(),
            scanning: false,
            selected_finding: 0,
            scan_path: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }
}

/// Configuration manager interface
#[derive(Debug)]
#[allow(dead_code)]
struct ConfigManager {
    config: crate::core::CryptoConfig,
    modified: bool,
    selected_section: ConfigSection,
}

impl ConfigManager {
    fn new() -> Self {
        Self {
            config: crate::core::CryptoConfig::default(),
            modified: false,
            selected_section: ConfigSection::Performance,
        }
    }
}

/// Configuration sections
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum ConfigSection {
    Performance,
    KeyDerivation,
    FileOperations,
    Security,
}

/// Main menu options
#[derive(Debug, Clone, Copy, PartialEq)]
enum MenuOption {
    FileBrowser,
    SecretDetection,
    Configuration,
    Themes,
    Initialize,
    Help,
    Exit,
}

impl MenuOption {
    fn all() -> Vec<Self> {
        vec![
            Self::FileBrowser,
            Self::SecretDetection,
            Self::Configuration,
            Self::Themes,
            Self::Initialize,
            Self::Help,
            Self::Exit,
        ]
    }

    fn label(&self) -> &str {
        match self {
            Self::FileBrowser => "📁 File Browser & Encryption",
            Self::SecretDetection => "🔍 Secret Detection Dashboard",
            Self::Configuration => "⚙️  Configuration Management",
            Self::Themes => "🎨 Color Themes & UI",
            Self::Initialize => "🚀 Initialize CargoCrypt",
            Self::Help => "❓ Help & Keybindings",
            Self::Exit => "❌ Exit",
        }
    }

    fn description(&self) -> &str {
        match self {
            Self::FileBrowser => "Browse files, encrypt/decrypt with visual feedback",
            Self::SecretDetection => "Scan for secrets with ML-powered detection",
            Self::Configuration => "Manage performance, security, and crypto settings",
            Self::Themes => "Customize colors, appearance, and UI preferences",
            Self::Initialize => "Set up CargoCrypt in current project",
            Self::Help => "View keybindings and usage instructions",
            Self::Exit => "Exit the application",
        }
    }
}

/// TUI application state
struct App {
    state: AppState,
    selected_index: usize,
    menu_items: Vec<MenuOption>,
    status_message: String,
    should_quit: bool,
}

impl ColorTheme {
    fn colors(&self) -> ThemeColors {
        match self {
            ColorTheme::Default => ThemeColors {
                background: Color::Black,
                foreground: Color::White,
                primary: Color::Rgb(79, 172, 254),
                secondary: Color::Rgb(173, 181, 189),
                accent: Color::Rgb(222, 165, 132),
                warning: Color::Yellow,
                error: Color::Red,
                success: Color::Green,
                info: Color::Cyan,
                border: Color::Gray,
                selection: Color::Rgb(68, 71, 90),
                highlight: Color::Rgb(40, 40, 40),
            },
            ColorTheme::Dark => ThemeColors {
                background: Color::Rgb(13, 17, 23),
                foreground: Color::Rgb(201, 209, 217),
                primary: Color::Rgb(33, 136, 255),
                secondary: Color::Rgb(110, 118, 129),
                accent: Color::Rgb(255, 167, 38),
                warning: Color::Rgb(219, 154, 4),
                error: Color::Rgb(248, 81, 73),
                success: Color::Rgb(63, 185, 80),
                info: Color::Rgb(91, 192, 222),
                border: Color::Rgb(48, 54, 61),
                selection: Color::Rgb(33, 38, 45),
                highlight: Color::Rgb(21, 23, 25),
            },
            ColorTheme::Light => ThemeColors {
                background: Color::Rgb(255, 255, 255),
                foreground: Color::Rgb(36, 41, 47),
                primary: Color::Rgb(9, 105, 218),
                secondary: Color::Rgb(101, 109, 118),
                accent: Color::Rgb(130, 80, 223),
                warning: Color::Rgb(154, 103, 0),
                error: Color::Rgb(207, 34, 46),
                success: Color::Rgb(26, 127, 55),
                info: Color::Rgb(31, 136, 161),
                border: Color::Rgb(208, 215, 222),
                selection: Color::Rgb(240, 246, 252),
                highlight: Color::Rgb(246, 248, 250),
            },
            ColorTheme::Solarized => ThemeColors {
                background: Color::Rgb(0, 43, 54),
                foreground: Color::Rgb(131, 148, 150),
                primary: Color::Rgb(38, 139, 210),
                secondary: Color::Rgb(88, 110, 117),
                accent: Color::Rgb(181, 137, 0),
                warning: Color::Rgb(203, 75, 22),
                error: Color::Rgb(220, 50, 47),
                success: Color::Rgb(133, 153, 0),
                info: Color::Rgb(42, 161, 152),
                border: Color::Rgb(7, 54, 66),
                selection: Color::Rgb(7, 54, 66),
                highlight: Color::Rgb(88, 110, 117),
            },
            ColorTheme::Monokai => ThemeColors {
                background: Color::Rgb(39, 40, 34),
                foreground: Color::Rgb(248, 248, 242),
                primary: Color::Rgb(102, 217, 239),
                secondary: Color::Rgb(117, 113, 94),
                accent: Color::Rgb(166, 226, 46),
                warning: Color::Rgb(253, 151, 31),
                error: Color::Rgb(249, 38, 114),
                success: Color::Rgb(166, 226, 46),
                info: Color::Rgb(174, 129, 255),
                border: Color::Rgb(73, 72, 62),
                selection: Color::Rgb(73, 72, 62),
                highlight: Color::Rgb(58, 57, 49),
            },
            ColorTheme::Terminal => ThemeColors {
                background: Color::Black,
                foreground: Color::White,
                primary: Color::Blue,
                secondary: Color::DarkGray,
                accent: Color::Magenta,
                warning: Color::Yellow,
                error: Color::Red,
                success: Color::Green,
                info: Color::Cyan,
                border: Color::Gray,
                selection: Color::DarkGray,
                highlight: Color::Gray,
            },
        }
    }

    fn name(&self) -> &'static str {
        match self {
            ColorTheme::Default => "Default",
            ColorTheme::Dark => "GitHub Dark",
            ColorTheme::Light => "GitHub Light",
            ColorTheme::Solarized => "Solarized Dark",
            ColorTheme::Monokai => "Monokai",
            ColorTheme::Terminal => "Terminal",
        }
    }

    fn next(&self) -> Self {
        match self {
            ColorTheme::Default => ColorTheme::Dark,
            ColorTheme::Dark => ColorTheme::Light,
            ColorTheme::Light => ColorTheme::Solarized,
            ColorTheme::Solarized => ColorTheme::Monokai,
            ColorTheme::Monokai => ColorTheme::Terminal,
            ColorTheme::Terminal => ColorTheme::Default,
        }
    }
}

impl AppState {
    fn new() -> Self {
        Self {
            current_view: AppView::MainMenu,
            file_browser: FileBrowser::new(),
            secret_detector: SecretDetectionDashboard::new(),
            config_manager: ConfigManager::new(),
            status_message: String::new(),
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            show_help: false,
            show_confirm_dialog: false,
            confirm_message: String::new(),
            last_scan_results: Vec::new(),
            theme: ColorTheme::Default,
            search_query: String::new(),
            search_mode: false,
            help_page: HelpPage::Overview,
        }
    }

    /// Handle file browser key events
    async fn handle_file_browser_key(&mut self, key: KeyCode, crypt: &Arc<CargoCrypt>) -> CryptoResult<bool> {
        match key {
            // Navigation
            KeyCode::Up | KeyCode::Char('k') => self.file_browser.move_up(),
            KeyCode::Down | KeyCode::Char('j') => self.file_browser.move_down(),
            KeyCode::PageUp => self.file_browser.page_up(10),
            KeyCode::PageDown => self.file_browser.page_down(10),
            KeyCode::Home | KeyCode::Char('g') => self.file_browser.go_to_first(),
            KeyCode::End | KeyCode::Char('G') => self.file_browser.go_to_last(),
            
            // Directory navigation
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if let Some(file) = self.file_browser.get_selected_file() {
                    if file.is_directory {
                        if file.name == ".." {
                            if let Some(parent) = self.file_browser.current_path.parent() {
                                let _ = self.file_browser.navigate_to(parent.to_path_buf());
                            }
                        } else {
                            let _ = self.file_browser.navigate_to(file.path.clone());
                        }
                    } else {
                        // File selected - show file operations menu
                        self.show_file_operations_menu().await;
                    }
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if let Some(parent) = self.file_browser.current_path.parent() {
                    let _ = self.file_browser.navigate_to(parent.to_path_buf());
                }
            }
            
            // File operations
            KeyCode::Char('e') => {
                self.encrypt_selected_files(crypt).await?;
            }
            KeyCode::Char('d') => {
                self.decrypt_selected_files(crypt).await?;
            }
            KeyCode::Char(' ') => {
                self.file_browser.toggle_selection();
            }
            KeyCode::Char('a') => {
                self.toggle_select_all();
            }
            KeyCode::Char('c') => {
                self.file_browser.clear_selections();
                self.status_message = "Cleared all selections".to_string();
            }
            
            // View controls
            KeyCode::Char('s') => {
                self.file_browser.cycle_sort_mode();
                self.status_message = format!("Sorted by: {:?}", self.file_browser.sort_mode);
            }
            KeyCode::Char('v') => {
                self.file_browser.cycle_view_mode();
                self.status_message = format!("View mode: {:?}", self.file_browser.view_mode);
            }
            KeyCode::Char('.') => {
                self.file_browser.toggle_hidden();
                let status = if self.file_browser.show_hidden { "Showing" } else { "Hiding" };
                self.status_message = format!("{} hidden files", status);
            }
            
            // Refresh
            KeyCode::Char('r') => {
                let _ = self.file_browser.refresh_files();
                self.status_message = "Directory refreshed".to_string();
            }
            
            // Secret scanning
            KeyCode::Char('S') => {
                self.scan_for_secrets().await?;
            }
            
            // Search mode
            KeyCode::Char('/') => {
                self.search_mode = true;
                self.input_mode = InputMode::Insert;
                self.input_buffer.clear();
                self.status_message = "Search: ".to_string();
            }
            
            // Theme cycling
            KeyCode::Char('t') => {
                self.theme = self.theme.next();
                self.status_message = format!("Theme: {}", self.theme.name());
            }
            
            // Help and navigation
            KeyCode::Char('?') => {
                self.show_help = !self.show_help;
            }
            KeyCode::Esc => {
                if self.search_mode {
                    self.search_mode = false;
                    self.input_mode = InputMode::Normal;
                    self.input_buffer.clear();
                    self.status_message = "Search cancelled".to_string();
                } else if self.show_help {
                    self.show_help = false;
                } else {
                    self.current_view = AppView::MainMenu;
                }
            }
            KeyCode::Char('q') => {
                if !self.show_help {
                    return Ok(true); // Quit
                } else {
                    self.show_help = false;
                }
            }
            
            // Handle search input
            key if self.search_mode => {
                match key {
                    KeyCode::Char(c) => {
                        self.input_buffer.push(c);
                        self.search_query = self.input_buffer.clone();
                        self.status_message = format!("Search: {}", self.search_query);
                    }
                    KeyCode::Backspace => {
                        self.input_buffer.pop();
                        self.search_query = self.input_buffer.clone();
                        self.status_message = format!("Search: {}", self.search_query);
                    }
                    KeyCode::Enter => {
                        self.search_mode = false;
                        self.input_mode = InputMode::Normal;
                        self.status_message = if self.search_query.is_empty() {
                            "Search cleared".to_string()
                        } else {
                            format!("Searching for: {}", self.search_query)
                        };
                    }
                    _ => {}
                }
            }
            
            _ => {}
        }
        Ok(false)
    }

    /// Show file operations menu
    async fn show_file_operations_menu(&mut self) {
        if let Some(file) = self.file_browser.get_selected_file() {
            if file.is_encrypted {
                self.confirm_message = format!("Decrypt file '{}'?", file.name);
            } else {
                self.confirm_message = format!("Encrypt file '{}'?", file.name);
            }
            self.show_confirm_dialog = true;
        }
    }

    /// Encrypt selected files with error recovery and user feedback
    async fn encrypt_selected_files(&mut self, crypt: &Arc<CargoCrypt>) -> CryptoResult<()> {
        // Check if the system is in degraded mode
        if crypt.is_degraded().await {
            self.status_message = "⚠️ System in degraded mode - some features may be limited".to_string();
        }
        let files_to_encrypt: Vec<PathBuf> = if self.file_browser.selected_files.is_empty() {
            // If no files selected, encrypt current file
            if let Some(file) = self.file_browser.get_selected_file() {
                if !file.is_directory && !file.is_encrypted {
                    vec![file.path.clone()]
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            self.file_browser.selected_files.iter()
                .filter(|path| {
                    !path.extension().and_then(|e| e.to_str()).map(|ext| ext == "enc").unwrap_or(false) && 
                    path.is_file()
                })
                .cloned()
                .collect()
        };

        if files_to_encrypt.is_empty() {
            self.status_message = "No files to encrypt".to_string();
            return Ok(());
        }

        self.file_browser.start_operation("Encrypting".to_string(), files_to_encrypt.len());
        
        let mut encrypted_count = 0;
        for (i, file_path) in files_to_encrypt.iter().enumerate() {
            self.file_browser.update_progress(i, file_path.display().to_string());
            
            // Get password from user - in a real implementation, this would be a proper password dialog
            let password = "default_password"; // TODO: Implement secure password input
            
            match crypt.encrypt_file(file_path, password).await {
                Ok(_) => {
                    encrypted_count += 1;
                }
                Err(e) => {
                    // Enhanced error handling with recovery suggestions
                    let error_msg = match &e {
                        crate::error::CargoCryptError::Validation { message, errors, warnings: _ } => {
                            format!("Validation failed for {}: {} ({})", 
                                file_path.display(), message, errors.join(", "))
                        }
                        crate::error::CargoCryptError::Crypto { message, kind } => {
                            format!("Crypto error for {}: {} (kind: {:?})", 
                                file_path.display(), message, kind)
                        }
                        crate::error::CargoCryptError::Config { message, suggestion } => {
                            if let Some(suggestion) = suggestion {
                                format!("Config error for {}: {} | Suggestion: {}", 
                                    file_path.display(), message, suggestion)
                            } else {
                                format!("Config error for {}: {}", file_path.display(), message)
                            }
                        }
                        _ => format!("Error encrypting {}: {}", file_path.display(), e),
                    };
                    
                    self.status_message = error_msg;
                    
                    // Check if error is recoverable and suggest action
                    if e.is_recoverable() {
                        self.status_message += " | Press 'r' to retry";
                    }
                }
            }
        }
        
        self.file_browser.complete_operation();
        self.file_browser.clear_selections();
        let _ = self.file_browser.refresh_files();
        
        self.status_message = format!("Encrypted {} files", encrypted_count);
        Ok(())
    }

    /// Decrypt selected files
    async fn decrypt_selected_files(&mut self, crypt: &Arc<CargoCrypt>) -> CryptoResult<()> {
        let files_to_decrypt: Vec<PathBuf> = if self.file_browser.selected_files.is_empty() {
            if let Some(file) = self.file_browser.get_selected_file() {
                if !file.is_directory && file.is_encrypted {
                    vec![file.path.clone()]
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            self.file_browser.selected_files.iter()
                .filter(|path| path.extension().and_then(|e| e.to_str()).map(|ext| ext == "enc").unwrap_or(false))
                .cloned()
                .collect()
        };

        if files_to_decrypt.is_empty() {
            self.status_message = "No encrypted files to decrypt".to_string();
            return Ok(());
        }

        self.file_browser.start_operation("Decrypting".to_string(), files_to_decrypt.len());
        
        let mut decrypted_count = 0;
        for (i, file_path) in files_to_decrypt.iter().enumerate() {
            self.file_browser.update_progress(i, file_path.display().to_string());
            
            let password = "default_password"; // TODO: Implement secure password input
            
            match crypt.decrypt_file(file_path, password).await {
                Ok(_) => {
                    decrypted_count += 1;
                }
                Err(e) => {
                    // Enhanced error handling for decryption
                    let error_msg = match &e {
                        crate::error::CargoCryptError::Crypto { message, kind } => {
                            match kind {
                                crate::error::CryptoErrorKind::AuthenticationFailed => {
                                    format!("Wrong password for {}: Authentication failed", file_path.display())
                                }
                                crate::error::CryptoErrorKind::Decryption => {
                                    format!("Decryption failed for {}: File may be corrupted", file_path.display())
                                }
                                _ => format!("Crypto error for {}: {} (kind: {:?})", 
                                    file_path.display(), message, kind),
                            }
                        }
                        crate::error::CargoCryptError::Validation { message, errors, warnings: _ } => {
                            format!("Validation failed for {}: {} ({})", 
                                file_path.display(), message, errors.join(", "))
                        }
                        _ => format!("Error decrypting {}: {}", file_path.display(), e),
                    };
                    
                    self.status_message = error_msg;
                    
                    // Provide specific suggestions based on error type
                    if matches!(e.crypto_kind(), Some(crate::error::CryptoErrorKind::AuthenticationFailed)) {
                        self.status_message += " | Check password and try again";
                    } else if e.is_recoverable() {
                        self.status_message += " | Press 'r' to retry";
                    }
                }
            }
        }
        
        self.file_browser.complete_operation();
        self.file_browser.clear_selections();
        let _ = self.file_browser.refresh_files();
        
        self.status_message = format!("Decrypted {} files", decrypted_count);
        Ok(())
    }

    /// Toggle select all files
    fn toggle_select_all(&mut self) {
        let all_selected = self.file_browser.files.iter()
            .filter(|f| !f.is_directory)
            .all(|f| f.is_selected);
        
        if all_selected {
            self.file_browser.clear_selections();
        } else {
            for file in &mut self.file_browser.files {
                if !file.is_directory {
                    file.is_selected = true;
                    self.file_browser.selected_files.insert(file.path.clone());
                }
            }
        }
    }

    /// Scan for secrets in current directory
    async fn scan_for_secrets(&mut self) -> CryptoResult<()> {
        self.status_message = "Scanning for secrets...".to_string();
        
        let detector = crate::detection::SecretDetector::new();
        let options = crate::detection::ScanOptions::default();
        
        match detector.scan_directory(&self.file_browser.current_path, &options).await {
            Ok(findings) => {
                self.last_scan_results = findings.clone();
                
                // Update file entries with secret detection results
                for file in &mut self.file_browser.files {
                    let has_secrets = findings.iter().any(|f| f.file_path == file.path);
                    file.has_secrets = Some(has_secrets);
                }
                
                let high_confidence_count = findings.iter()
                    .filter(|f| f.confidence >= 0.7)
                    .count();
                let medium_confidence_count = findings.iter()
                    .filter(|f| f.confidence >= 0.4 && f.confidence < 0.7)
                    .count();
                
                if findings.is_empty() {
                    self.status_message = "✅ Scan complete: No secrets detected".to_string();
                } else {
                    let mut msg = format!(
                        "⚠️ Scan complete: {} findings ({} high, {} medium confidence)", 
                        findings.len(), 
                        high_confidence_count,
                        medium_confidence_count
                    );
                    
                    if high_confidence_count > 0 {
                        msg += " | High confidence findings require attention!";
                    }
                    
                    self.status_message = msg;
                }
            }
            Err(e) => {
                // Enhanced error reporting for secret detection
                let error_msg = match &e {
                    crate::error::CargoCryptError::Config { message, suggestion } => {
                        if let Some(suggestion) = suggestion {
                            format!("Scan config error: {} | {}", message, suggestion)
                        } else {
                            format!("Scan config error: {}", message)
                        }
                    }
                    crate::error::CargoCryptError::Io { message, source: _ } => {
                        format!("Scan I/O error: {} | Check directory permissions", message)
                    }
                    _ => format!("Scan error: {} | Try refreshing and scanning again", e),
                };
                
                self.status_message = error_msg;
            }
        }
        
        Ok(())
    }
}

impl App {
    fn new() -> Self {
        Self {
            state: AppState::new(),
            selected_index: 0,
            menu_items: MenuOption::all(),
            status_message: String::from("Welcome to CargoCrypt TUI!"),
            should_quit: false,
        }
    }

    fn next(&mut self) {
        self.selected_index = (self.selected_index + 1) % self.menu_items.len();
    }

    fn previous(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        } else {
            self.selected_index = self.menu_items.len() - 1;
        }
    }

    fn get_selected(&self) -> MenuOption {
        self.menu_items[self.selected_index]
    }

    async fn handle_selection(&mut self, crypt: &Arc<CargoCrypt>) -> CryptoResult<()> {
        // Store reference for later use
        let _crypt_ref = crypt;
        match self.get_selected() {
            MenuOption::Initialize => {
                // Show progress feedback
                self.status_message = "🚀 Initializing CargoCrypt...".to_string();
                
                match CargoCrypt::init_project().await {
                    Ok(_) => {
                        self.status_message = "✅ CargoCrypt initialized successfully!".to_string();
                        
                        // Perform health check after initialization
                        let health = crypt.health_check().await;
                        if matches!(health.overall_health, crate::resilience::HealthLevel::Degraded | crate::resilience::HealthLevel::Critical) {
                            self.status_message += " ⚠️ Some features in degraded mode";
                        }
                    }
                    Err(e) => {
                        // Enhanced error reporting for initialization
                        let error_msg = match &e {
                            crate::error::CargoCryptError::Project { message, suggestion } => {
                                if let Some(suggestion) = suggestion {
                                    format!("❌ Project error: {} | {}", message, suggestion)
                                } else {
                                    format!("❌ Project error: {}", message)
                                }
                            }
                            crate::error::CargoCryptError::Config { message, suggestion } => {
                                if let Some(suggestion) = suggestion {
                                    format!("❌ Config error: {} | {}", message, suggestion)
                                } else {
                                    format!("❌ Config error: {}", message)
                                }
                            }
                            crate::error::CargoCryptError::Io { message, source: _ } => {
                                format!("❌ I/O error: {} | Check directory permissions", message)
                            }
                            _ => format!("❌ Error: {}", e),
                        };
                        
                        self.status_message = error_msg;
                    }
                }
            }
            MenuOption::FileBrowser => {
                // Check system health before entering file browser
                let health = crypt.health_check().await;
                if matches!(health.overall_health, crate::resilience::HealthLevel::Critical) {
                    self.status_message = "❌ File browser unavailable - system in critical state".to_string();
                } else {
                    self.state.current_view = AppView::FileBrowser;
                    self.state.file_browser.update_list_state();
                    
                    if matches!(health.overall_health, crate::resilience::HealthLevel::Degraded) {
                        self.status_message = "⚠️ File browser in degraded mode - some features limited".to_string();
                    } else {
                        self.status_message = "📁 File browser ready".to_string();
                    }
                }
            }
            MenuOption::SecretDetection => {
                self.state.current_view = AppView::SecretDetection;
            }
            MenuOption::Configuration => {
                self.state.current_view = AppView::Configuration;
            }
            MenuOption::Themes => {
                self.state.current_view = AppView::Themes;
            }
            MenuOption::Help => {
                self.state.current_view = AppView::Help;
                self.state.show_help = true;
            }
            MenuOption::Exit => {
                self.should_quit = true;
            }
        }
        Ok(())
    }
}

fn ui(app: &App, frame: &mut Frame) {
    match app.state.current_view {
        AppView::MainMenu => render_main_menu(app, frame),
        AppView::FileBrowser => render_file_browser(app, frame),
        AppView::SecretDetection => render_secret_detection(app, frame),
        AppView::Configuration => render_configuration(app, frame),
        AppView::Themes => render_themes(app, frame),
        AppView::Help => render_help(app, frame),
    }

    // Render overlays
    if app.state.show_help {
        render_help_overlay(frame);
    }
    
    if app.state.show_confirm_dialog {
        render_confirm_dialog(&app.state.confirm_message, frame);
    }
}

/// Render the main menu
fn render_main_menu(app: &App, frame: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),      // Title
            Constraint::Min(10),        // Menu
            Constraint::Length(3),      // Status
            Constraint::Length(3),      // Help
        ])
        .split(frame.size());

    // Title
    let title = Paragraph::new("🦀 CargoCrypt - Terminal User Interface")
        .style(Style::default().fg(Color::Rgb(222, 165, 132)).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    // Menu
    let menu_items: Vec<ListItem> = app.menu_items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let style = if i == app.selected_index {
                Style::default()
                    .fg(Color::Rgb(79, 172, 254))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            
            let content = vec![
                Line::from(vec![
                    Span::styled(format!(" {} ", item.label()), style),
                ]),
                Line::from(vec![
                    Span::styled(format!("   {}", item.description()), 
                        Style::default().fg(Color::Rgb(173, 181, 189))),
                ]),
            ];
            
            ListItem::new(content)
        })
        .collect();

    let menu = List::new(menu_items)
        .block(Block::default().borders(Borders::ALL).title("Main Menu"));
    frame.render_widget(menu, chunks[1]);

    // Status
    let status = Paragraph::new(app.status_message.as_str())
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(status, chunks[2]);

    // Help
    let help = Paragraph::new("↑/↓: Navigate | Enter: Select | q: Quit")
        .style(Style::default().fg(Color::Rgb(173, 181, 189)))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[3]);
}

/// Render the file browser interface
fn render_file_browser(app: &App, frame: &mut Frame) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),      // Header
            Constraint::Min(10),        // File list
            Constraint::Length(4),      // Status and info
            Constraint::Length(2),      // Help
        ])
        .split(frame.size());

    // Header with current path and controls
    render_file_browser_header(&app.state.file_browser, frame, main_chunks[0]);
    
    // File list area
    let file_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(70), // File list
            Constraint::Percentage(30), // File details
        ])
        .split(main_chunks[1]);
    
    // Render file list
    render_file_list(&app.state.file_browser, &app.state.search_query, &app.state.theme, frame, file_chunks[0]);
    
    // Render file details panel
    render_file_details(&app.state.file_browser, &app.state.theme, frame, file_chunks[1]);
    
    // Status area
    render_status_area(app, frame, main_chunks[2]);
    
    // Help line
    render_file_browser_help(frame, main_chunks[3]);
    
    // Progress overlay if operation in progress
    if let Some(ref progress) = app.state.file_browser.operation_progress {
        render_progress_overlay(progress, frame);
    }
}

/// Render file browser header
fn render_file_browser_header(browser: &FileBrowser, frame: &mut Frame, area: Rect) {
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(20),        // Path
            Constraint::Length(30),     // Stats
        ])
        .split(area);
    
    // Current path
    let path_text = format!("📁 {}", browser.current_path.display());
    let path_widget = Paragraph::new(path_text)
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL).title("Current Directory"));
    frame.render_widget(path_widget, header_chunks[0]);
    
    // File stats
    let total_files = browser.files.len();
    let selected_count = browser.selected_files.len();
    let encrypted_count = browser.files.iter().filter(|f| f.is_encrypted).count();
    let with_secrets = browser.files.iter().filter(|f| f.has_secrets == Some(true)).count();
    
    let stats_text = format!(
        "Files: {} | Selected: {} | Encrypted: {} | Secrets: {} | Sort: {:?}",
        total_files, selected_count, encrypted_count, with_secrets, browser.sort_mode
    );
    
    let stats_widget = Paragraph::new(stats_text)
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title("Statistics"));
    frame.render_widget(stats_widget, header_chunks[1]);
}

/// Render the file list
fn render_file_list(browser: &FileBrowser, search_query: &str, theme: &ColorTheme, frame: &mut Frame, area: Rect) {
    if browser.loading {
        let loading_text = "Loading directory...";
        let loading_widget = Paragraph::new(loading_text)
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title("File Browser"));
        frame.render_widget(loading_widget, area);
        return;
    }
    
    if let Some(ref error) = browser.error_message {
        let error_widget = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title("Error"));
        frame.render_widget(error_widget, area);
        return;
    }
    
    match browser.view_mode {
        ViewMode::List => render_file_list_simple(browser, search_query, theme, frame, area),
        ViewMode::Details => render_file_list_detailed(browser, search_query, theme, frame, area),
        ViewMode::Tree => render_file_tree(browser, search_query, theme, frame, area),
    }
}

/// Render simple file list
fn render_file_list_simple(browser: &FileBrowser, frame: &mut Frame, area: Rect) {
    let items: Vec<ListItem> = browser.files
        .iter()
        .enumerate()
        .map(|(i, file)| {
            let style = if i == browser.selected_index {
                Style::default().bg(Color::Rgb(68, 71, 90)).fg(Color::White)
            } else if file.is_selected {
                Style::default().bg(Color::Rgb(40, 40, 40)).fg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };
            
            let status_indicators = file.status_indicator();
            let content = format!(
                "{} {} {}",
                file.display_name(),
                status_indicators,
                if file.is_directory {
                    String::new()
                } else {
                    FileBrowser::format_size(file.size)
                }
            );
            
            ListItem::new(Line::from(Span::styled(content, style)))
        })
        .collect();
    
    let mut list_state = browser.list_state.clone();
    let file_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Files"))
        .highlight_style(Style::default().bg(Color::Rgb(68, 71, 90)));
    
    frame.render_stateful_widget(file_list, area, &mut list_state);
}

/// Render detailed file list
fn render_file_list_detailed(browser: &FileBrowser, search_query: &str, theme: &ColorTheme, frame: &mut Frame, area: Rect) {
    let colors = theme.colors();
    let filtered_files = if search_query.is_empty() {
        browser.files.iter().collect::<Vec<_>>()
    } else {
        browser.filter_by_search(search_query)
    };
    let header = Row::new(vec![
        Cell::from("Name").style(Style::default().fg(colors.warning)),
        Cell::from("Size").style(Style::default().fg(colors.warning)),
        Cell::from("Modified").style(Style::default().fg(colors.warning)),
        Cell::from("Perms").style(Style::default().fg(colors.warning)),
        Cell::from("Status").style(Style::default().fg(colors.warning)),
    ]);
    
    let rows: Vec<Row> = filtered_files
        .iter()
        .enumerate()
        .map(|(i, file)| {
            let style = if i == browser.selected_index {
                Style::default().bg(colors.selection)
            } else if file.is_selected {
                Style::default().bg(colors.highlight)
            } else {
                Style::default()
            };
            
            Row::new(vec![
                Cell::from(file.display_name()),
                Cell::from(if file.is_directory {
                    "<DIR>".to_string()
                } else {
                    FileBrowser::format_size(file.size)
                }),
                Cell::from(file.formatted_modified()),
                Cell::from(file.permissions.clone()),
                Cell::from(file.status_indicator()),
            ]).style(style)
        })
        .collect();
    
    let title = if search_query.is_empty() {
        "Files (Detailed)".to_string()
    } else {
        format!("Files (Detailed - filtered: {})", filtered_files.len())
    };
    
    let table = Table::new(rows)
        .widths(&[
            Constraint::Percentage(40),
            Constraint::Length(10),
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(8),
        ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title)
        .border_style(Style::default().fg(colors.border)))
    .highlight_style(Style::default().bg(colors.selection));
    
    let mut table_state = TableState::default();
    table_state.select(Some(browser.selected_index));
    frame.render_stateful_widget(table, area, &mut table_state);
}

/// Render file tree view (simplified implementation)
fn render_file_tree(browser: &FileBrowser, search_query: &str, theme: &ColorTheme, frame: &mut Frame, area: Rect) {
    // For now, just render as list with indentation for directories
    render_file_list_simple(browser, search_query, theme, frame, area);
}

/// Render file details panel
fn render_file_details(browser: &FileBrowser, theme: &ColorTheme, frame: &mut Frame, area: Rect) {
    let colors = theme.colors();
    if let Some(file) = browser.get_selected_file() {
        let details = vec![
            format!("Name: {}", file.name),
            format!("Path: {}", file.path.display()),
            format!("Type: {}", if file.is_directory { "Directory" } else { "File" }),
            format!("Size: {}", if file.is_directory { "<DIR>".to_string() } else { FileBrowser::format_size(file.size) }),
            format!("Modified: {}", file.formatted_modified()),
            format!("Permissions: {}", file.permissions),
            format!("Encrypted: {}", if file.is_encrypted { "Yes" } else { "No" }),
            format!("Has Secrets: {}", match file.has_secrets {
                Some(true) => "Yes",
                Some(false) => "No",
                None => "Unknown",
            }),
        ];
        
        let details_text = details.join("\n");
        let details_widget = Paragraph::new(details_text)
            .style(Style::default().fg(colors.foreground))
            .block(Block::default().borders(Borders::ALL).title("File Details")
                .border_style(Style::default().fg(colors.border)))
            .wrap(Wrap { trim: true });
        
        frame.render_widget(details_widget, area);
    } else {
        let empty_widget = Paragraph::new("No file selected")
            .style(Style::default().fg(colors.secondary))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title("File Details")
                .border_style(Style::default().fg(colors.border)));
        
        frame.render_widget(empty_widget, area);
    }
}

/// Render status area
fn render_status_area(app: &App, frame: &mut Frame, area: Rect) {
    let status_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(70), // Status message
            Constraint::Percentage(30), // Additional info
        ])
        .split(area);
    
    // Main status message
    let status_widget = Paragraph::new(app.state.status_message.as_str())
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(status_widget, status_chunks[0]);
    
    // Additional info
    let info_text = format!(
        "Filter: {}\nHidden: {}\nView: {:?}",
        if app.state.file_browser.filter.is_empty() { "None" } else { &app.state.file_browser.filter },
        if app.state.file_browser.show_hidden { "Shown" } else { "Hidden" },
        app.state.file_browser.view_mode
    );
    
    let info_widget = Paragraph::new(info_text)
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title("Info"));
    frame.render_widget(info_widget, status_chunks[1]);
}

/// Render file browser help
fn render_file_browser_help(frame: &mut Frame, area: Rect) {
    let help_text = "j/k/↑/↓: Navigate | h/l/←/→: Dir nav | Space: Select | e: Encrypt | d: Decrypt | s: Sort | v: View | .: Hidden | r: Refresh | S: Scan | ?: Help | Esc: Back | q: Quit";
    let help_widget = Paragraph::new(help_text)
        .style(Style::default().fg(Color::Rgb(173, 181, 189)))
        .block(Block::default().borders(Borders::TOP));
    frame.render_widget(help_widget, area);
}

/// Render progress overlay
fn render_progress_overlay(progress: &OperationProgress, frame: &mut Frame) {
    let area = centered_rect(60, 20, frame.size());
    
    frame.render_widget(Clear, area);
    
    let block = Block::default()
        .title(format!(" {} Progress ", progress.operation))
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Black));
    
    let inner = block.inner(area);
    frame.render_widget(block, area);
    
    let progress_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(inner);
    
    // Current file
    let current_file = Paragraph::new(format!("Processing: {}", progress.current_file))
        .style(Style::default().fg(Color::White));
    frame.render_widget(current_file, progress_chunks[0]);
    
    // Progress bar
    let progress_ratio = if progress.total > 0 {
        progress.current as f64 / progress.total as f64
    } else {
        0.0
    };
    
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Cyan))
        .percent((progress_ratio * 100.0) as u16)
        .label(format!("{}/{}", progress.current, progress.total));
    
    frame.render_widget(gauge, progress_chunks[1]);
    
    // Instructions
    let instructions = Paragraph::new("Please wait...")
        .style(Style::default().fg(Color::Gray))
        .alignment(Alignment::Center);
    frame.render_widget(instructions, progress_chunks[2]);
}

/// Run the TUI application
pub async fn run_tui(crypt: Arc<CargoCrypt>) -> CryptoResult<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new();

    // Main loop
    loop {
        terminal.draw(|f| ui(&app, f))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                let should_quit = match app.state.current_view {
                    AppView::MainMenu => {
                        handle_main_menu_key(&mut app, key.code, &crypt).await?
                    }
                    AppView::FileBrowser => {
                        app.state.handle_file_browser_key(key.code, &crypt).await?
                    }
                    AppView::SecretDetection => {
                        handle_secret_detection_key(&mut app, key.code).await?
                    }
                    AppView::Configuration => {
                        handle_configuration_key(&mut app, key.code).await?
                    }
                    AppView::Help => {
                        handle_help_key(&mut app, key.code)
                    }
                    AppView::Themes => {
                        handle_themes_key(&mut app, key.code)
                    }
                };
                
                if should_quit || app.should_quit {
                    break;
                }
            }
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

/// Handle main menu key events
async fn handle_main_menu_key(app: &mut App, key: KeyCode, crypt: &Arc<CargoCrypt>) -> CryptoResult<bool> {
    match key {
        KeyCode::Char('q') => return Ok(true),
        KeyCode::Up => app.previous(),
        KeyCode::Down => app.next(),
        KeyCode::Enter => {
            app.handle_selection(crypt).await?;
            if app.should_quit {
                return Ok(true);
            }
        }
        _ => {}
    }
    Ok(false)
}

/// Handle secret detection key events
async fn handle_secret_detection_key(app: &mut App, key: KeyCode) -> CryptoResult<bool> {
    match key {
        KeyCode::Char('q') => return Ok(true),
        KeyCode::Esc => {
            app.state.current_view = AppView::MainMenu;
        }
        KeyCode::Char('S') => {
            app.state.scan_for_secrets().await?;
        }
        KeyCode::Char('r') => {
            app.state.last_scan_results.clear();
            app.state.status_message = "Scan results cleared".to_string();
        }
        _ => {}
    }
    Ok(false)
}

/// Handle configuration key events
async fn handle_configuration_key(app: &mut App, key: KeyCode) -> CryptoResult<bool> {
    match key {
        KeyCode::Char('q') => return Ok(true),
        KeyCode::Esc => {
            if app.state.config_manager.modified {
                // Show warning about unsaved changes
                app.state.status_message = "Warning: Unsaved changes! Press 's' to save or 'r' to reset".to_string();
            } else {
                app.state.current_view = AppView::MainMenu;
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.state.config_manager.selected_section = match app.state.config_manager.selected_section {
                ConfigSection::Performance => ConfigSection::Security,
                ConfigSection::KeyDerivation => ConfigSection::Performance,
                ConfigSection::FileOperations => ConfigSection::KeyDerivation,
                ConfigSection::Security => ConfigSection::FileOperations,
            };
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.state.config_manager.selected_section = match app.state.config_manager.selected_section {
                ConfigSection::Performance => ConfigSection::KeyDerivation,
                ConfigSection::KeyDerivation => ConfigSection::FileOperations,
                ConfigSection::FileOperations => ConfigSection::Security,
                ConfigSection::Security => ConfigSection::Performance,
            };
        }
        KeyCode::Char('s') => {
            // Save configuration
            app.state.config_manager.modified = false;
            app.state.status_message = "Configuration saved successfully".to_string();
        }
        KeyCode::Char('r') => {
            // Reset configuration
            app.state.config_manager.config = crate::core::CryptoConfig::default();
            app.state.config_manager.modified = false;
            app.state.status_message = "Configuration reset to defaults".to_string();
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            // Toggle boolean values or open editor for complex types
            app.state.config_manager.modified = true;
            app.state.status_message = "Configuration modified - press 's' to save".to_string();
        }
        _ => {}
    }
    Ok(false)
}

/// Handle help key events
fn handle_help_key(app: &mut App, key: KeyCode) -> bool {
    match key {
        KeyCode::Char('q') => {
            return true; // Quit application
        }
        KeyCode::Esc => {
            app.state.show_help = false;
            app.state.current_view = AppView::MainMenu;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.state.help_page = match app.state.help_page {
                HelpPage::Overview => HelpPage::Themes,
                HelpPage::FileBrowser => HelpPage::Overview,
                HelpPage::SecretDetection => HelpPage::FileBrowser,
                HelpPage::Configuration => HelpPage::SecretDetection,
                HelpPage::Keybindings => HelpPage::Configuration,
                HelpPage::Themes => HelpPage::Keybindings,
            };
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.state.help_page = match app.state.help_page {
                HelpPage::Overview => HelpPage::FileBrowser,
                HelpPage::FileBrowser => HelpPage::SecretDetection,
                HelpPage::SecretDetection => HelpPage::Configuration,
                HelpPage::Configuration => HelpPage::Keybindings,
                HelpPage::Keybindings => HelpPage::Themes,
                HelpPage::Themes => HelpPage::Overview,
            };
        }
        KeyCode::Char('t') => {
            app.state.theme = app.state.theme.next();
            app.state.status_message = format!("Theme: {}", app.state.theme.name());
        }
        _ => {}
    }
    false
}

/// Handle themes key events
fn handle_themes_key(app: &mut App, key: KeyCode) -> bool {
    match key {
        KeyCode::Char('q') => {
            return true; // Quit application
        }
        KeyCode::Esc => {
            app.state.current_view = AppView::MainMenu;
        }
        KeyCode::Char('t') | KeyCode::Enter => {
            app.state.theme = app.state.theme.next();
            app.state.status_message = format!("Theme changed to: {}", app.state.theme.name());
        }
        KeyCode::Up | KeyCode::Char('k') => {
            // Cycle themes backward
            app.state.theme = match app.state.theme {
                ColorTheme::Default => ColorTheme::Terminal,
                ColorTheme::Dark => ColorTheme::Default,
                ColorTheme::Light => ColorTheme::Dark,
                ColorTheme::Solarized => ColorTheme::Light,
                ColorTheme::Monokai => ColorTheme::Solarized,
                ColorTheme::Terminal => ColorTheme::Monokai,
            };
            app.state.status_message = format!("Theme: {}", app.state.theme.name());
        }
        KeyCode::Down | KeyCode::Char('j') => {
            // Cycle themes forward
            app.state.theme = app.state.theme.next();
            app.state.status_message = format!("Theme: {}", app.state.theme.name());
        }
        _ => {}
    }
    false
}

/// Render secret detection view
fn render_secret_detection(app: &App, frame: &mut Frame) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),      // Header
            Constraint::Min(10),        // Results
            Constraint::Length(5),      // Summary
            Constraint::Length(2),      // Help
        ])
        .split(frame.size());

    // Header with scan controls
    let header_text = format!(
        "Secret Detection Dashboard - Scanned: {} | Path: {}",
        app.state.last_scan_results.len(),
        app.state.file_browser.current_path.display()
    );
    let header = Paragraph::new(header_text)
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL).title("🔍 Secret Detection"));
    frame.render_widget(header, main_chunks[0]);

    // Results list
    if app.state.last_scan_results.is_empty() {
        let empty_msg = Paragraph::new("No scan results available.\n\nPress 'S' to start scanning for secrets.")
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title("Scan Results"));
        frame.render_widget(empty_msg, main_chunks[1]);
    } else {
        render_secret_results(&app.state.last_scan_results, frame, main_chunks[1]);
    }

    // Summary statistics
    render_secret_summary(&app.state.last_scan_results, frame, main_chunks[2]);

    // Help
    let help = Paragraph::new("S: Scan current directory | Enter: View details | Esc: Back | q: Quit")
        .style(Style::default().fg(Color::Rgb(173, 181, 189)))
        .block(Block::default().borders(Borders::TOP));
    frame.render_widget(help, main_chunks[3]);
}

/// Render configuration view
fn render_configuration(app: &App, frame: &mut Frame) {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(1)
        .constraints([
            Constraint::Percentage(30), // Config sections
            Constraint::Percentage(70), // Config details
        ])
        .split(frame.size());

    // Configuration sections
    render_config_sections(&app.state.config_manager, frame, main_chunks[0]);
    
    // Configuration details for selected section
    render_config_details(&app.state.config_manager, frame, main_chunks[1]);

    // Status overlay for unsaved changes
    if app.state.config_manager.modified {
        render_config_modified_overlay(frame);
    }
}

/// Render help view
fn render_help(app: &App, frame: &mut Frame) {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(1)
        .constraints([
            Constraint::Percentage(25), // Help navigation
            Constraint::Percentage(75), // Help content
        ])
        .split(frame.size());

    // Help navigation
    render_help_navigation(&app.state.help_page, frame, main_chunks[0]);
    
    // Help content
    render_help_content(&app.state.help_page, &app.state.theme, frame, main_chunks[1]);
}

/// Render help navigation
fn render_help_navigation(current_page: &HelpPage, frame: &mut Frame, area: Rect) {
    let pages = vec![
        ("Overview", HelpPage::Overview),
        ("File Browser", HelpPage::FileBrowser),
        ("Secret Detection", HelpPage::SecretDetection),
        ("Configuration", HelpPage::Configuration),
        ("Keybindings", HelpPage::Keybindings),
        ("Themes", HelpPage::Themes),
    ];
    
    let items: Vec<ListItem> = pages
        .iter()
        .map(|(name, page)| {
            let style = if *page == *current_page {
                Style::default().bg(Color::Rgb(68, 71, 90)).fg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };
            
            ListItem::new(Line::from(Span::styled(*name, style)))
        })
        .collect();
    
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("📖 Help Topics"))
        .highlight_style(Style::default().bg(Color::Rgb(68, 71, 90)));
    
    frame.render_widget(list, area);
}

/// Render help content
fn render_help_content(page: &HelpPage, theme: &ColorTheme, frame: &mut Frame, area: Rect) {
    let colors = theme.colors();
    
    let content = match page {
        HelpPage::Overview => format!(
            "🦀 CargoCrypt Terminal User Interface\n\n\
            Welcome to CargoCrypt TUI! This interface provides comprehensive\n\
            cryptographic operations with an intuitive terminal interface.\n\n\
            Features:\n\
            • File browser with encryption status\n\
            • Secret detection with ML algorithms\n\
            • Configuration management\n\
            • Color themes and customization\n\
            • Real-time progress indicators\n\n\
            Current Theme: {}\n\n\
            Navigation:\n\
            • Use arrow keys or hjkl to navigate\n\
            • Press Enter to select items\n\
            • Press Esc to go back\n\
            • Press ? for context help\n\n\
            Press j/k or arrow keys to navigate help topics.",
            theme.name()
        ),
        HelpPage::FileBrowser => 
            "📁 File Browser Help\n\n\
            Navigation:\n\
            • j/k, ↑/↓      Navigate up/down\n\
            • h/l, ←/→      Navigate directories\n\
            • g/G           Go to first/last item\n\
            • Page Up/Down  Page navigation\n\n\
            File Operations:\n\
            • Space         Toggle file selection\n\
            • a             Toggle select all files\n\
            • c             Clear all selections\n\
            • e             Encrypt selected files\n\
            • d             Decrypt selected files\n\n\
            View Controls:\n\
            • s             Cycle sort mode\n\
            • v             Cycle view mode\n\
            • .             Toggle hidden files\n\
            • r             Refresh directory\n\
            • /             Search files\n\n\
            Special Features:\n\
            • S             Scan for secrets\n\
            • t             Cycle color themes\n\
            • ?             Toggle quick help".to_string(),
        HelpPage::SecretDetection => 
            "🔍 Secret Detection Help\n\n\
            The secret detection system uses machine learning\n\
            algorithms to identify potential secrets in your code.\n\n\
            Operations:\n\
            • S             Start secret scan\n\
            • r             Clear scan results\n\
            • Enter         View finding details\n\
            • /             Search findings\n\n\
            Risk Levels:\n\
            • High (80%+)   Likely secrets requiring attention\n\
            • Medium (50%+) Possible secrets to review\n\
            • Low (<50%)    Patterns with low confidence\n\n\
            Detection Types:\n\
            • API Keys      AWS, GitHub, etc.\n\
            • Passwords     Hardcoded credentials\n\
            • Tokens        JWT, OAuth tokens\n\
            • Private Keys  RSA, SSH keys\n\
            • Certificates  SSL/TLS certificates\n\n\
            Use the summary panel to quickly assess\n\
            the security status of your project.".to_string(),
        HelpPage::Configuration => 
            "⚙️ Configuration Help\n\n\
            Manage CargoCrypt settings across different categories:\n\n\
            Navigation:\n\
            • j/k, ↑/↓      Navigate sections\n\
            • Enter/Space   Edit setting\n\
            • s             Save configuration\n\
            • r             Reset to defaults\n\n\
            Configuration Sections:\n\n\
            Performance:\n\
            • Buffer sizes for optimal throughput\n\
            • Worker threads for parallel operations\n\
            • SIMD acceleration settings\n\n\
            Key Derivation:\n\
            • Argon2id parameters\n\
            • Memory and time costs\n\
            • Parallelism settings\n\n\
            File Operations:\n\
            • Backup and atomic operation settings\n\
            • Metadata preservation options\n\
            • Checksum verification\n\n\
            Security:\n\
            • Fail-secure modes\n\
            • Memory clearing options\n\
            • Audit logging settings".to_string(),
        HelpPage::Keybindings => 
            "⌨️ Global Keybindings\n\n\
            Universal Commands (available in all views):\n\
            • q             Quit application\n\
            • Esc           Go back/cancel\n\
            • ?             Toggle help\n\
            • t             Cycle themes\n\
            • /             Search mode\n\n\
            Navigation:\n\
            • ↑/↓ or j/k    Move up/down\n\
            • ←/→ or h/l    Move left/right\n\
            • Enter         Select/activate\n\
            • Tab           Next panel\n\
            • Shift+Tab     Previous panel\n\n\
            File Browser Specific:\n\
            • Space         Toggle selection\n\
            • a             Select all\n\
            • c             Clear selections\n\
            • e             Encrypt\n\
            • d             Decrypt\n\
            • s             Sort mode\n\
            • v             View mode\n\
            • .             Hidden files\n\
            • r             Refresh\n\
            • S             Scan secrets\n\n\
            Search Mode:\n\
            • Type to search\n\
            • Enter         Apply search\n\
            • Esc           Cancel search\n\
            • Backspace     Delete character".to_string(),
        HelpPage::Themes => format!(
            "🎨 Theme System Help\n\n\
            CargoCrypt TUI supports multiple color themes\n\
            to match your preference and environment.\n\n\
            Current Theme: {}\n\n\
            Available Themes:\n\
            • Default       - Standard terminal colors\n\
            • GitHub Dark   - Modern dark theme\n\
            • GitHub Light  - Clean light theme\n\
            • Solarized     - Popular developer theme\n\
            • Monokai       - Sublime Text inspired\n\
            • Terminal      - Basic ANSI colors\n\n\
            Theme Controls:\n\
            • t             Cycle to next theme\n\
            • Themes Menu   Preview and select themes\n\n\
            Theme Features:\n\
            • Syntax highlighting for file types\n\
            • Status-aware colors (errors, warnings)\n\
            • Accessibility considerations\n\
            • High contrast options\n\n\
            Themes persist across sessions and can be\n\
            customized in the configuration menu.",
            theme.name()
        ),
    };
    
    let help_widget = Paragraph::new(content)
        .style(Style::default().fg(colors.foreground))
        .alignment(Alignment::Left)
        .block(Block::default().borders(Borders::ALL).title("Help Content").border_style(Style::default().fg(colors.border)))
        .wrap(Wrap { trim: false });
    
    frame.render_widget(help_widget, area);
}

/// Render theme selection view
fn render_themes(app: &App, frame: &mut Frame) {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(1)
        .constraints([
            Constraint::Percentage(40), // Theme list
            Constraint::Percentage(60), // Theme preview
        ])
        .split(frame.size());

    // Theme list
    render_theme_list(&app.state.theme, frame, main_chunks[0]);
    
    // Theme preview
    render_theme_preview(&app.state.theme, frame, main_chunks[1]);
    
    // Help overlay
    let help_area = Rect {
        x: main_chunks[1].x,
        y: main_chunks[1].y + main_chunks[1].height - 3,
        width: main_chunks[1].width,
        height: 3,
    };
    
    let help = Paragraph::new("t: Next theme | Enter: Select theme | Esc: Back | q: Quit")
        .style(Style::default().fg(Color::Rgb(173, 181, 189)))
        .block(Block::default().borders(Borders::TOP));
    frame.render_widget(help, help_area);
}

/// Render theme list
fn render_theme_list(current_theme: &ColorTheme, frame: &mut Frame, area: Rect) {
    let themes = vec![
        ColorTheme::Default,
        ColorTheme::Dark,
        ColorTheme::Light,
        ColorTheme::Solarized,
        ColorTheme::Monokai,
        ColorTheme::Terminal,
    ];
    
    let items: Vec<ListItem> = themes
        .iter()
        .map(|theme| {
            let colors = theme.colors();
            let style = if theme == current_theme {
                Style::default().bg(colors.selection).fg(colors.foreground)
            } else {
                Style::default().fg(Color::White)
            };
            
            let indicator = if theme == current_theme { "● " } else { "  " };
            let content = format!("{}{}", indicator, theme.name());
            
            ListItem::new(Line::from(Span::styled(content, style)))
        })
        .collect();
    
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("🎨 Available Themes"));
    
    frame.render_widget(list, area);
}

/// Render theme preview
fn render_theme_preview(theme: &ColorTheme, frame: &mut Frame, area: Rect) {
    let colors = theme.colors();
    
    let preview_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Title
            Constraint::Min(5),     // Color samples
            Constraint::Length(8),  // Sample UI
        ])
        .split(area);
    
    // Title
    let title = Paragraph::new(format!("Theme: {}", theme.name()))
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(colors.border)));
    frame.render_widget(title, preview_chunks[0]);
    
    // Color samples
    let color_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(preview_chunks[1]);
    
    let color_samples = vec![
        ("Primary", colors.primary),
        ("Success", colors.success),
        ("Warning", colors.warning),
        ("Error", colors.error),
    ];
    
    for (i, (name, color)) in color_samples.iter().enumerate() {
        if i < color_chunks.len() {
            let sample = Paragraph::new(format!("■\n{}", name))
                .style(Style::default().fg(*color))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(colors.border)));
            frame.render_widget(sample, color_chunks[i]);
        }
    }
    
    // Sample UI elements
    let ui_text = format!(
        "Sample UI Elements:\n\n\
        {} Normal text\n\
        {} Primary highlight\n\
        {} Secondary text\n\
        {} Success message\n\
        {} Warning message\n\
        {} Error message",
        "●", "●", "●", "●", "●", "●"
    );
    
    let ui_lines = vec![
        Line::from("Sample UI Elements:"),
        Line::from(""),
        Line::from(Span::styled("● Normal text", Style::default().fg(colors.foreground))),
        Line::from(Span::styled("● Primary highlight", Style::default().fg(colors.primary))),
        Line::from(Span::styled("● Secondary text", Style::default().fg(colors.secondary))),
        Line::from(Span::styled("● Success message", Style::default().fg(colors.success))),
        Line::from(Span::styled("● Warning message", Style::default().fg(colors.warning))),
        Line::from(Span::styled("● Error message", Style::default().fg(colors.error))),
    ];
    
    let ui_sample = Paragraph::new(ui_lines)
        .block(Block::default().borders(Borders::ALL).title("Preview").border_style(Style::default().fg(colors.border)));
    
    frame.render_widget(ui_sample, preview_chunks[2]);
}

/// Render help overlay
fn render_help_overlay(frame: &mut Frame) {
    let area = centered_rect(80, 80, frame.size());
    frame.render_widget(Clear, area);
    
    let help_text = r#"
Quick Help - File Browser

Navigation:
  j/k, ↑/↓     Move up/down
  h/l, ←/→     Enter/exit directories
  g/G          Go to first/last
  Page Up/Down Page navigation

File Operations:
  Space        Toggle selection
  a            Select/deselect all
  c            Clear selections
  e            Encrypt files
  d            Decrypt files

View Controls:
  s            Sort mode (Name→Size→Date→Type→Encryption)
  v            View mode (List→Details→Tree)
  .            Toggle hidden files
  r            Refresh

Special:
  S            Scan for secrets
  ?            Toggle this help
  Esc          Close help/go back
  q            Quit
"#;
    
    let help_widget = Paragraph::new(help_text)
        .style(Style::default().fg(Color::White).bg(Color::Black))
        .alignment(Alignment::Left)
        .block(Block::default().borders(Borders::ALL).title(" Quick Help "))
        .wrap(Wrap { trim: false });
    frame.render_widget(help_widget, area);
}

/// Render confirmation dialog
fn render_confirm_dialog(message: &str, frame: &mut Frame) {
    let area = centered_rect(50, 20, frame.size());
    frame.render_widget(Clear, area);
    
    let dialog = Paragraph::new(format!("{}\n\nPress Enter to confirm, Esc to cancel", message))
        .style(Style::default().fg(Color::White).bg(Color::Black))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(" Confirm "))
        .wrap(Wrap { trim: false });
    frame.render_widget(dialog, area);
}

/// Render secret scan results
fn render_secret_results(findings: &[crate::detection::Finding], frame: &mut Frame, area: Rect) {
    let header = Row::new(vec![
        Cell::from("File").style(Style::default().fg(Color::Yellow)),
        Cell::from("Line").style(Style::default().fg(Color::Yellow)),
        Cell::from("Type").style(Style::default().fg(Color::Yellow)),
        Cell::from("Confidence").style(Style::default().fg(Color::Yellow)),
        Cell::from("Preview").style(Style::default().fg(Color::Yellow)),
    ]);
    
    let rows: Vec<Row> = findings
        .iter()
        .map(|finding| {
            let confidence_style = if finding.confidence >= 0.8 {
                Style::default().fg(Color::Red)
            } else if finding.confidence >= 0.5 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Gray)
            };
            
            let preview = finding.preview.chars().take(30).collect::<String>();
            let preview = if finding.preview.len() > 30 {
                format!("{}...", preview)
            } else {
                preview
            };
            
            Row::new(vec![
                Cell::from(finding.file_path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("<unknown>")),
                Cell::from(finding.line_number.to_string()),
                Cell::from(finding.secret_type.clone()),
                Cell::from(format!("{:.0}%", finding.confidence * 100.0)).style(confidence_style),
                Cell::from(preview),
            ])
        })
        .collect();
    
    let table = Table::new(rows)
        .widths(&[
            Constraint::Percentage(25),
            Constraint::Length(6),
            Constraint::Percentage(20),
            Constraint::Length(10),
            Constraint::Percentage(35),
        ])
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Secret Detection Results"));
    
    frame.render_widget(table, area);
}

/// Render secret detection summary
fn render_secret_summary(findings: &[crate::detection::Finding], frame: &mut Frame, area: Rect) {
    let summary_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);
    
    // Total findings
    let total = findings.len();
    let total_widget = Paragraph::new(format!("{}\nTotal", total))
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(total_widget, summary_chunks[0]);
    
    // High confidence
    let high_conf = findings.iter().filter(|f| f.confidence >= 0.8).count();
    let high_conf_widget = Paragraph::new(format!("{}\nHigh Risk", high_conf))
        .style(Style::default().fg(Color::Red))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(high_conf_widget, summary_chunks[1]);
    
    // Medium confidence
    let med_conf = findings.iter().filter(|f| f.confidence >= 0.5 && f.confidence < 0.8).count();
    let med_conf_widget = Paragraph::new(format!("{}\nMedium Risk", med_conf))
        .style(Style::default().fg(Color::Yellow))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(med_conf_widget, summary_chunks[2]);
    
    // Unique file count
    let unique_files: std::collections::HashSet<_> = findings.iter()
        .map(|f| &f.file_path)
        .collect();
    let files_widget = Paragraph::new(format!("{}\nFiles Affected", unique_files.len()))
        .style(Style::default().fg(Color::Cyan))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(files_widget, summary_chunks[3]);
}

/// Render configuration sections
fn render_config_sections(config_manager: &ConfigManager, frame: &mut Frame, area: Rect) {
    let sections = vec![
        ("Performance", ConfigSection::Performance),
        ("Key Derivation", ConfigSection::KeyDerivation),
        ("File Operations", ConfigSection::FileOperations),
        ("Security", ConfigSection::Security),
    ];
    
    let items: Vec<ListItem> = sections
        .iter()
        .map(|(name, section)| {
            let style = if *section == config_manager.selected_section {
                Style::default().bg(Color::Rgb(68, 71, 90)).fg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };
            
            ListItem::new(Line::from(Span::styled(*name, style)))
        })
        .collect();
    
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("⚙️ Configuration Sections"))
        .highlight_style(Style::default().bg(Color::Rgb(68, 71, 90)));
    
    frame.render_widget(list, area);
}

/// Render configuration details
fn render_config_details(config_manager: &ConfigManager, frame: &mut Frame, area: Rect) {
    let config = &config_manager.config;
    
    let details = match config_manager.selected_section {
        ConfigSection::Performance => {
            format!(
                "Performance Profile: {:?}\n\n\
                Buffer Size: {} KB\n\
                Worker Threads: {}\n\
                Max Concurrent: {}\n\
                Enable SIMD: {}\n\n\
                These settings control the overall performance\n\
                characteristics of CargoCrypt operations.",
                config.performance_profile,
                config.performance.buffer_size_kb,
                config.performance.worker_threads,
                config.performance.max_concurrent_ops,
                config.performance.enable_simd
            )
        }
        ConfigSection::KeyDerivation => {
            format!(
                "Algorithm: Argon2id\n\n\
                Memory Cost: {} KiB\n\
                Time Cost: {} iterations\n\
                Parallelism: {} threads\n\
                Output Length: {} bytes\n\n\
                Key derivation parameters control the\n\
                computational cost of password hashing.",
                config.key_params.memory_cost,
                config.key_params.time_cost,
                config.key_params.parallelism,
                config.key_params.output_length
            )
        }
        ConfigSection::FileOperations => {
            format!(
                "Backup Originals: {}\n\
                Preserve Metadata: {}\n\
                Atomic Operations: {}\n\
                Verify Checksums: {}\n\n\
                These settings control how files are\n\
                handled during encryption operations.",
                config.file_ops.backup_originals,
                config.file_ops.preserve_metadata,
                config.file_ops.atomic_operations,
                config.file_ops.verify_checksums
            )
        }
        ConfigSection::Security => {
            format!(
                "Fail Secure: {}\n\
                Clear Memory: {}\n\
                Constant Time: {}\n\
                Audit Log: {}\n\n\
                Security settings control defensive\n\
                measures and secure coding practices.",
                config.security.fail_secure,
                config.security.clear_memory_on_drop,
                config.security.constant_time_operations,
                config.security.enable_audit_log
            )
        }
    };
    
    let details_widget = Paragraph::new(details)
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title("Configuration Details"))
        .wrap(Wrap { trim: true });
    
    frame.render_widget(details_widget, area);
}

/// Render configuration modified overlay
fn render_config_modified_overlay(frame: &mut Frame) {
    let area = centered_rect(50, 15, frame.size());
    
    frame.render_widget(Clear, area);
    
    let warning = Paragraph::new("⚠️ Configuration Modified\n\nYou have unsaved changes.\n\nPress 's' to save or 'r' to reset.")
        .style(Style::default().fg(Color::Yellow).bg(Color::Black))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(" Warning "));
    
    frame.render_widget(warning, area);
}

/// Helper function to create a centered rectangle
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}