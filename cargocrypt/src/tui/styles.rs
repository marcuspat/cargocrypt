//! Cargo-themed styling for CargoCrypt TUI
//!
//! Provides consistent colors, styles, and animations inspired by Rust and Cargo.

use ratatui::{
    style::{Color, Modifier, Style},
    symbols,
};

/// Cargo-themed color palette
#[derive(Debug, Clone, Copy)]
pub struct CargoColors;

impl CargoColors {
    /// Rust orange (primary brand color)
    pub const RUST_ORANGE: Color = Color::Rgb(222, 165, 132);
    
    /// Rust dark orange (accent)
    pub const RUST_DARK_ORANGE: Color = Color::Rgb(210, 125, 74);
    
    /// Cargo blue (complementary)
    pub const CARGO_BLUE: Color = Color::Rgb(79, 172, 254);
    
    /// Dark blue for backgrounds
    pub const DARK_BLUE: Color = Color::Rgb(35, 55, 85);
    
    /// Success green
    pub const SUCCESS_GREEN: Color = Color::Rgb(88, 166, 88);
    
    /// Warning yellow
    pub const WARNING_YELLOW: Color = Color::Rgb(255, 193, 7);
    
    /// Error red
    pub const ERROR_RED: Color = Color::Rgb(220, 53, 69);
    
    /// Info cyan
    pub const INFO_CYAN: Color = Color::Rgb(23, 162, 184);
    
    /// Background dark
    pub const BACKGROUND_DARK: Color = Color::Rgb(33, 37, 41);
    
    /// Background light
    pub const BACKGROUND_LIGHT: Color = Color::Rgb(248, 249, 250);
    
    /// Text primary
    pub const TEXT_PRIMARY: Color = Color::Rgb(255, 255, 255);
    
    /// Text secondary
    pub const TEXT_SECONDARY: Color = Color::Rgb(173, 181, 189);
    
    /// Text muted
    pub const TEXT_MUTED: Color = Color::Rgb(108, 117, 125);
    
    /// Border color
    pub const BORDER: Color = Color::Rgb(52, 58, 64);
    
    /// Highlight color
    pub const HIGHLIGHT: Color = Color::Rgb(255, 235, 59);
    
    /// Selected background
    pub const SELECTED_BG: Color = Color::Rgb(40, 44, 52);
}

/// Cargo-themed style presets
pub struct CargoStyle;

impl CargoStyle {
    /// Default text style
    pub fn default() -> Style {
        Style::default()
            .fg(CargoColors::TEXT_PRIMARY)
            .bg(Color::Reset)
    }
    
    /// Primary brand style (Rust orange)
    pub fn primary() -> Style {
        Style::default()
            .fg(CargoColors::RUST_ORANGE)
            .add_modifier(Modifier::BOLD)
    }
    
    /// Accent style (Cargo blue)
    pub fn accent() -> Style {
        Style::default()
            .fg(CargoColors::CARGO_BLUE)
            .add_modifier(Modifier::BOLD)
    }
    
    /// Success style
    pub fn success() -> Style {
        Style::default()
            .fg(CargoColors::SUCCESS_GREEN)
            .add_modifier(Modifier::BOLD)
    }
    
    /// Warning style
    pub fn warning() -> Style {
        Style::default()
            .fg(CargoColors::WARNING_YELLOW)
            .add_modifier(Modifier::BOLD)
    }
    
    /// Error style
    pub fn error() -> Style {
        Style::default()
            .fg(CargoColors::ERROR_RED)
            .add_modifier(Modifier::BOLD)
    }
    
    /// Info style
    pub fn info() -> Style {
        Style::default()
            .fg(CargoColors::INFO_CYAN)
            .add_modifier(Modifier::BOLD)
    }
    
    /// Muted text style
    pub fn muted() -> Style {
        Style::default()
            .fg(CargoColors::TEXT_MUTED)
    }
    
    /// Secondary text style
    pub fn secondary() -> Style {
        Style::default()
            .fg(CargoColors::TEXT_SECONDARY)
    }
    
    /// Highlight style
    pub fn highlight() -> Style {
        Style::default()
            .fg(CargoColors::HIGHLIGHT)
            .add_modifier(Modifier::BOLD)
    }
    
    /// Selected item style
    pub fn selected() -> Style {
        Style::default()
            .fg(CargoColors::TEXT_PRIMARY)
            .bg(CargoColors::SELECTED_BG)
            .add_modifier(Modifier::BOLD)
    }
    
    /// Border style
    pub fn border() -> Style {
        Style::default()
            .fg(CargoColors::BORDER)
    }
    
    /// Title style
    pub fn title() -> Style {
        Style::default()
            .fg(CargoColors::RUST_ORANGE)
            .add_modifier(Modifier::BOLD)
    }
    
    /// Subtitle style
    pub fn subtitle() -> Style {
        Style::default()
            .fg(CargoColors::CARGO_BLUE)
            .add_modifier(Modifier::BOLD)
    }
    
    /// Code style (for displaying code snippets)
    pub fn code() -> Style {
        Style::default()
            .fg(CargoColors::TEXT_PRIMARY)
            .bg(CargoColors::BACKGROUND_DARK)
            .add_modifier(Modifier::ITALIC)
    }
    
    /// Command style (for vim-like commands)
    pub fn command() -> Style {
        Style::default()
            .fg(CargoColors::CARGO_BLUE)
            .bg(CargoColors::BACKGROUND_DARK)
            .add_modifier(Modifier::BOLD)
    }
    
    /// Status bar style
    pub fn status_bar() -> Style {
        Style::default()
            .fg(CargoColors::TEXT_PRIMARY)
            .bg(CargoColors::BACKGROUND_DARK)
    }
    
    /// Progress bar style
    pub fn progress() -> Style {
        Style::default()
            .fg(CargoColors::RUST_ORANGE)
            .bg(CargoColors::BACKGROUND_DARK)
    }
    
    /// Gauge style for security metrics
    pub fn security_gauge(level: SecurityLevel) -> Style {
        match level {
            SecurityLevel::Secure => Self::success(),
            SecurityLevel::Warning => Self::warning(),
            SecurityLevel::Danger => Self::error(),
            SecurityLevel::Critical => Style::default()
                .fg(CargoColors::ERROR_RED)
                .bg(Color::Rgb(139, 0, 0))
                .add_modifier(Modifier::BOLD | Modifier::BLINK),
        }
    }
    
    /// Activity severity style
    pub fn activity_severity(severity: ActivitySeverity) -> Style {
        match severity {
            ActivitySeverity::Info => Self::info(),
            ActivitySeverity::Success => Self::success(),
            ActivitySeverity::Warning => Self::warning(),
            ActivitySeverity::Error => Self::error(),
        }
    }
    
    /// Vim mode style
    pub fn vim_mode(mode: VimMode) -> Style {
        match mode {
            VimMode::Normal => Self::default(),
            VimMode::Insert => Self::accent(),
            VimMode::Visual => Self::warning(),
            VimMode::Command => Self::command(),
        }
    }
}

/// Security level for styling
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityLevel {
    Secure,
    Warning,
    Danger,
    Critical,
}

/// Activity severity for styling
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ActivitySeverity {
    Info,
    Success,
    Warning,
    Error,
}

/// Vim mode for styling
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VimMode {
    Normal,
    Insert,
    Visual,
    Command,
}

/// Cargo-themed symbols and icons
pub struct CargoSymbols;

impl CargoSymbols {
    /// Cargo package symbol
    pub const PACKAGE: &'static str = "📦";
    
    /// Rust crab symbol
    pub const CRAB: &'static str = "🦀";
    
    /// Lock symbol for security
    pub const LOCK: &'static str = "🔒";
    
    /// Unlock symbol for insecurity
    pub const UNLOCK: &'static str = "🔓";
    
    /// Key symbol for encryption
    pub const KEY: &'static str = "🔑";
    
    /// Shield symbol for protection
    pub const SHIELD: &'static str = "🛡️";
    
    /// Warning symbol
    pub const WARNING: &'static str = "⚠️";
    
    /// Error symbol
    pub const ERROR: &'static str = "❌";
    
    /// Success symbol
    pub const SUCCESS: &'static str = "✅";
    
    /// Info symbol
    pub const INFO: &'static str = "ℹ️";
    
    /// Gear symbol for settings
    pub const GEAR: &'static str = "⚙️";
    
    /// Search symbol
    pub const SEARCH: &'static str = "🔍";
    
    /// File symbol
    pub const FILE: &'static str = "📄";
    
    /// Folder symbol
    pub const FOLDER: &'static str = "📁";
    
    /// Network symbol
    pub const NETWORK: &'static str = "🌐";
    
    /// Clock symbol
    pub const CLOCK: &'static str = "🕐";
    
    /// Chart symbol
    pub const CHART: &'static str = "📊";
    
    /// Terminal symbol
    pub const TERMINAL: &'static str = "💻";
    
    /// Spinning wheel frames for loading
    pub const SPINNER: &'static [&'static str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    
    /// Cargo loading animation frames
    pub const CARGO_SPINNER: &'static [&'static str] = &["📦", "📫", "📪", "📬"];
    
    /// Progress bar characters
    pub const PROGRESS_FULL: &'static str = "█";
    pub const PROGRESS_EMPTY: &'static str = "░";
    pub const PROGRESS_PARTIAL: &'static [&'static str] = &["▏", "▎", "▍", "▌", "▋", "▊", "▉"];
    
    /// Box drawing characters for borders
    pub const BOX_HORIZONTAL: &'static str = "─";
    pub const BOX_VERTICAL: &'static str = "│";
    pub const BOX_TOP_LEFT: &'static str = "┌";
    pub const BOX_TOP_RIGHT: &'static str = "┐";
    pub const BOX_BOTTOM_LEFT: &'static str = "└";
    pub const BOX_BOTTOM_RIGHT: &'static str = "┘";
    pub const BOX_TEE_UP: &'static str = "┴";
    pub const BOX_TEE_DOWN: &'static str = "┬";
    pub const BOX_TEE_LEFT: &'static str = "┤";
    pub const BOX_TEE_RIGHT: &'static str = "├";
    pub const BOX_CROSS: &'static str = "┼";
    
    /// Vim-style navigation arrows
    pub const VIM_UP: &'static str = "↑";
    pub const VIM_DOWN: &'static str = "↓";
    pub const VIM_LEFT: &'static str = "←";
    pub const VIM_RIGHT: &'static str = "→";
}

/// Animation helpers
pub struct CargoAnimation;

impl CargoAnimation {
    /// Get spinner frame
    pub fn spinner_frame(frame: usize) -> &'static str {
        CargoSymbols::SPINNER[frame % CargoSymbols::SPINNER.len()]
    }
    
    /// Get cargo spinner frame
    pub fn cargo_spinner_frame(frame: usize) -> &'static str {
        CargoSymbols::CARGO_SPINNER[frame % CargoSymbols::CARGO_SPINNER.len()]
    }
    
    /// Get progress bar with partial characters
    pub fn progress_bar(progress: f64, width: usize) -> String {
        let filled = (progress * width as f64) as usize;
        let partial = ((progress * width as f64) % 1.0 * 8.0) as usize;
        
        let mut bar = String::new();
        
        // Full blocks
        for _ in 0..filled {
            bar.push_str(CargoSymbols::PROGRESS_FULL);
        }
        
        // Partial block
        if partial > 0 && filled < width {
            bar.push_str(CargoSymbols::PROGRESS_PARTIAL[partial - 1]);
        }
        
        // Empty blocks
        let remaining = width - filled - if partial > 0 { 1 } else { 0 };
        for _ in 0..remaining {
            bar.push_str(CargoSymbols::PROGRESS_EMPTY);
        }
        
        bar
    }
    
    /// Get pulsing color based on phase
    pub fn pulse_color(phase: f64, base_color: Color) -> Color {
        let intensity = (phase.sin() + 1.0) / 2.0;
        
        match base_color {
            Color::Rgb(r, g, b) => {
                let new_r = ((r as f64 * intensity) as u8).min(255);
                let new_g = ((g as f64 * intensity) as u8).min(255);
                let new_b = ((b as f64 * intensity) as u8).min(255);
                Color::Rgb(new_r, new_g, new_b)
            }
            _ => base_color,
        }
    }
    
    /// Get breathing effect alpha
    pub fn breathing_alpha(phase: f64) -> f64 {
        (phase.sin() + 1.0) / 2.0 * 0.5 + 0.5
    }
}

/// Theme configuration
#[derive(Debug, Clone)]
pub struct Theme {
    pub name: String,
    pub colors: ThemeColors,
    pub animations_enabled: bool,
    pub vim_mode_enabled: bool,
}

/// Theme colors
#[derive(Debug, Clone)]
pub struct ThemeColors {
    pub primary: Color,
    pub secondary: Color,
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub info: Color,
    pub background: Color,
    pub text: Color,
    pub border: Color,
    pub highlight: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            name: "Cargo".to_string(),
            colors: ThemeColors {
                primary: CargoColors::RUST_ORANGE,
                secondary: CargoColors::CARGO_BLUE,
                success: CargoColors::SUCCESS_GREEN,
                warning: CargoColors::WARNING_YELLOW,
                error: CargoColors::ERROR_RED,
                info: CargoColors::INFO_CYAN,
                background: CargoColors::BACKGROUND_DARK,
                text: CargoColors::TEXT_PRIMARY,
                border: CargoColors::BORDER,
                highlight: CargoColors::HIGHLIGHT,
            },
            animations_enabled: true,
            vim_mode_enabled: true,
        }
    }
}

impl Theme {
    /// Create a light theme variant
    pub fn light() -> Self {
        Self {
            name: "Cargo Light".to_string(),
            colors: ThemeColors {
                primary: CargoColors::RUST_DARK_ORANGE,
                secondary: CargoColors::CARGO_BLUE,
                success: CargoColors::SUCCESS_GREEN,
                warning: Color::Rgb(255, 152, 0),
                error: CargoColors::ERROR_RED,
                info: CargoColors::INFO_CYAN,
                background: CargoColors::BACKGROUND_LIGHT,
                text: Color::Rgb(33, 37, 41),
                border: Color::Rgb(222, 226, 230),
                highlight: Color::Rgb(255, 193, 7),
            },
            animations_enabled: true,
            vim_mode_enabled: true,
        }
    }
    
    /// Create a high contrast theme for accessibility
    pub fn high_contrast() -> Self {
        Self {
            name: "High Contrast".to_string(),
            colors: ThemeColors {
                primary: Color::White,
                secondary: Color::Yellow,
                success: Color::Green,
                warning: Color::Yellow,
                error: Color::Red,
                info: Color::Cyan,
                background: Color::Black,
                text: Color::White,
                border: Color::White,
                highlight: Color::Yellow,
            },
            animations_enabled: false,
            vim_mode_enabled: true,
        }
    }
}