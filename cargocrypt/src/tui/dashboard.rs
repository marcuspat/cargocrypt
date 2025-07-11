//! Dashboard module for CargoCrypt TUI
//!
//! Provides the main dashboard view with security overview, metrics, and cargo-themed animations.

use ratatui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Chart, Dataset, Gauge, List, ListItem, Paragraph, Sparkline, Wrap,
    },
    Frame,
};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    detection::{Finding, SecretDetector},
    CargoCrypt, CryptoResult,
};

use super::{AnimationState, CargoStyle};

/// Dashboard state and data
#[derive(Debug, Clone)]
pub struct Dashboard {
    /// CargoCrypt instance
    crypt: Option<Arc<CargoCrypt>>,
    /// Security overview
    security_overview: SecurityOverview,
    /// Recent activity
    recent_activity: VecDeque<ActivityItem>,
    /// Performance metrics over time
    metrics_history: VecDeque<MetricsSnapshot>,
    /// System status
    system_status: SystemStatus,
    /// Quick stats
    quick_stats: QuickStats,
    /// Last update time
    last_update: Instant,
}

/// Security overview data
#[derive(Debug, Clone)]
pub struct SecurityOverview {
    pub total_secrets: usize,
    pub encrypted_secrets: usize,
    pub vulnerabilities: usize,
    pub last_scan: Option<Instant>,
    pub scan_status: ScanStatus,
    pub risk_level: RiskLevel,
}

/// Activity item for recent activity feed
#[derive(Debug, Clone)]
pub struct ActivityItem {
    pub timestamp: Instant,
    pub action: String,
    pub details: String,
    pub severity: ActivitySeverity,
}

/// Activity severity levels
#[derive(Debug, Clone, PartialEq)]
pub enum ActivitySeverity {
    Info,
    Warning,
    Error,
    Success,
}

/// Metrics snapshot for history tracking
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub timestamp: Instant,
    pub secrets_count: usize,
    pub scan_time: Duration,
    pub memory_usage: u64,
    pub cpu_usage: f64,
}

/// System status information
#[derive(Debug, Clone)]
pub struct SystemStatus {
    pub uptime: Duration,
    pub memory_usage: u64,
    pub disk_usage: u64,
    pub network_status: NetworkStatus,
    pub git_status: GitStatus,
}

/// Network connectivity status
#[derive(Debug, Clone)]
pub enum NetworkStatus {
    Connected,
    Disconnected,
    Limited,
}

/// Git repository status
#[derive(Debug, Clone)]
pub struct GitStatus {
    pub clean: bool,
    pub branch: String,
    pub commits_ahead: usize,
    pub commits_behind: usize,
    pub modified_files: usize,
}

/// Quick statistics
#[derive(Debug, Clone)]
pub struct QuickStats {
    pub files_scanned: usize,
    pub secrets_found: usize,
    pub false_positives: usize,
    pub scan_coverage: f64,
}

/// Scan status
#[derive(Debug, Clone, PartialEq)]
pub enum ScanStatus {
    Idle,
    Running,
    Completed,
    Failed,
}

/// Risk level assessment
#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Dashboard {
    fn default() -> Self {
        Self {
            crypt: None,
            security_overview: SecurityOverview {
                total_secrets: 0,
                encrypted_secrets: 0,
                vulnerabilities: 0,
                last_scan: None,
                scan_status: ScanStatus::Idle,
                risk_level: RiskLevel::Low,
            },
            recent_activity: VecDeque::with_capacity(100),
            metrics_history: VecDeque::with_capacity(100),
            system_status: SystemStatus {
                uptime: Duration::from_secs(0),
                memory_usage: 0,
                disk_usage: 0,
                network_status: NetworkStatus::Connected,
                git_status: GitStatus {
                    clean: true,
                    branch: "main".to_string(),
                    commits_ahead: 0,
                    commits_behind: 0,
                    modified_files: 0,
                },
            },
            quick_stats: QuickStats {
                files_scanned: 0,
                secrets_found: 0,
                false_positives: 0,
                scan_coverage: 0.0,
            },
            last_update: Instant::now(),
        }
    }
}

impl Dashboard {
    /// Initialize the dashboard
    pub async fn init(&mut self, crypt: Arc<CargoCrypt>) -> CryptoResult<()> {
        self.crypt = Some(crypt);
        self.refresh().await?;
        
        // Add initial activity
        self.add_activity(
            "System Started",
            "CargoCrypt TUI initialized",
            ActivitySeverity::Success,
        );
        
        Ok(())
    }

    /// Refresh dashboard data
    pub async fn refresh(&mut self) -> CryptoResult<()> {
        if let Some(crypt) = &self.crypt {
            // Update security overview
            self.update_security_overview(crypt).await?;
            
            // Update system status
            self.update_system_status().await?;
            
            // Update quick stats
            self.update_quick_stats().await?;
            
            // Add metrics snapshot
            self.add_metrics_snapshot();
            
            self.last_update = Instant::now();
        }
        
        Ok(())
    }

    /// Update security overview
    async fn update_security_overview(&mut self, crypt: &Arc<CargoCrypt>) -> CryptoResult<()> {
        // This would integrate with the actual secret detection system
        // For now, we'll simulate some data
        
        self.security_overview.total_secrets = 42; // Example
        self.security_overview.encrypted_secrets = 38;
        self.security_overview.vulnerabilities = 3;
        
        // Assess risk level
        self.security_overview.risk_level = match self.security_overview.vulnerabilities {
            0 => RiskLevel::Low,
            1..=3 => RiskLevel::Medium,
            4..=7 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };
        
        Ok(())
    }

    /// Update system status
    async fn update_system_status(&mut self) -> CryptoResult<()> {
        // Update uptime
        self.system_status.uptime = Duration::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        
        // Update git status (if in a git repo)
        if let Ok(repo) = git2::Repository::open(".") {
            let head = repo.head()?;
            if let Some(branch_name) = head.shorthand() {
                self.system_status.git_status.branch = branch_name.to_string();
            }
            
            // Check if working directory is clean
            let statuses = repo.statuses(None)?;
            self.system_status.git_status.clean = statuses.is_empty();
            self.system_status.git_status.modified_files = statuses.len();
        }
        
        Ok(())
    }

    /// Update quick stats
    async fn update_quick_stats(&mut self) -> CryptoResult<()> {
        // These would be updated from actual scanning operations
        self.quick_stats.files_scanned = 157;
        self.quick_stats.secrets_found = 12;
        self.quick_stats.false_positives = 2;
        self.quick_stats.scan_coverage = 0.85;
        
        Ok(())
    }

    /// Add activity item
    pub fn add_activity(&mut self, action: &str, details: &str, severity: ActivitySeverity) {
        let item = ActivityItem {
            timestamp: Instant::now(),
            action: action.to_string(),
            details: details.to_string(),
            severity,
        };
        
        self.recent_activity.push_front(item);
        
        // Keep only last 100 items
        while self.recent_activity.len() > 100 {
            self.recent_activity.pop_back();
        }
    }

    /// Add metrics snapshot
    fn add_metrics_snapshot(&mut self) {
        let snapshot = MetricsSnapshot {
            timestamp: Instant::now(),
            secrets_count: self.security_overview.total_secrets,
            scan_time: Duration::from_millis(250), // Example
            memory_usage: self.system_status.memory_usage,
            cpu_usage: 15.5, // Example
        };
        
        self.metrics_history.push_front(snapshot);
        
        // Keep only last 100 snapshots
        while self.metrics_history.len() > 100 {
            self.metrics_history.pop_back();
        }
    }

    /// Update from background operations
    pub async fn update(&mut self) -> CryptoResult<()> {
        // Check if we need to refresh
        if self.last_update.elapsed() > Duration::from_secs(30) {
            self.refresh().await?;
        }
        
        Ok(())
    }

    /// Render the dashboard
    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect, animation: &AnimationState) {
        // Split the area into main sections
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(7),  // Header with quick stats
                Constraint::Min(0),     // Main content
            ])
            .split(area);

        // Render header
        self.render_header(f, main_chunks[0], animation);
        
        // Split main content
        let content_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(60), // Left panel
                Constraint::Percentage(40), // Right panel
            ])
            .split(main_chunks[1]);

        // Render left panel
        self.render_left_panel(f, content_chunks[0], animation);
        
        // Render right panel
        self.render_right_panel(f, content_chunks[1], animation);
    }

    /// Render header with quick stats
    fn render_header<B: Backend>(&self, f: &mut Frame<B>, area: Rect, animation: &AnimationState) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
            ])
            .split(area);

        // Cargo animation frames
        let cargo_frames = ["📦", "📫", "📪", "📬"];
        let cargo_icon = cargo_frames[animation.spinning_cargo];

        // Security gauge
        let security_ratio = if self.security_overview.total_secrets > 0 {
            self.security_overview.encrypted_secrets as f64 / self.security_overview.total_secrets as f64
        } else {
            1.0
        };

        let security_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(format!("{} Security", cargo_icon)))
            .gauge_style(self.risk_level_style())
            .ratio(security_ratio)
            .label(format!("{:.1}%", security_ratio * 100.0));

        f.render_widget(security_gauge, chunks[0]);

        // Secrets counter
        let secrets_text = vec![
            Line::from(vec![
                Span::styled("Total: ", Style::default().fg(Color::Gray)),
                Span::styled(self.security_overview.total_secrets.to_string(), CargoStyle::highlight()),
            ]),
            Line::from(vec![
                Span::styled("Encrypted: ", Style::default().fg(Color::Gray)),
                Span::styled(self.security_overview.encrypted_secrets.to_string(), CargoStyle::success()),
            ]),
            Line::from(vec![
                Span::styled("Vulnerabilities: ", Style::default().fg(Color::Gray)),
                Span::styled(self.security_overview.vulnerabilities.to_string(), CargoStyle::error()),
            ]),
        ];

        let secrets_info = Paragraph::new(secrets_text)
            .block(Block::default().borders(Borders::ALL).title("🔐 Secrets"))
            .alignment(Alignment::Left);

        f.render_widget(secrets_info, chunks[1]);

        // Scan status
        let scan_status_text = match self.security_overview.scan_status {
            ScanStatus::Idle => "Idle",
            ScanStatus::Running => "Running...",
            ScanStatus::Completed => "Completed",
            ScanStatus::Failed => "Failed",
        };

        let scan_progress = if self.security_overview.scan_status == ScanStatus::Running {
            animation.security_scan_progress
        } else {
            1.0
        };

        let scan_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("🛡️ Scan Status"))
            .gauge_style(CargoStyle::accent())
            .ratio(scan_progress)
            .label(scan_status_text);

        f.render_widget(scan_gauge, chunks[2]);

        // System status
        let git_status = if self.system_status.git_status.clean {
            "Clean"
        } else {
            "Modified"
        };

        let system_text = vec![
            Line::from(vec![
                Span::styled("Branch: ", Style::default().fg(Color::Gray)),
                Span::styled(&self.system_status.git_status.branch, CargoStyle::highlight()),
            ]),
            Line::from(vec![
                Span::styled("Status: ", Style::default().fg(Color::Gray)),
                Span::styled(git_status, if self.system_status.git_status.clean {
                    CargoStyle::success()
                } else {
                    CargoStyle::warning()
                }),
            ]),
            Line::from(vec![
                Span::styled("Files: ", Style::default().fg(Color::Gray)),
                Span::styled(self.system_status.git_status.modified_files.to_string(), CargoStyle::default()),
            ]),
        ];

        let system_info = Paragraph::new(system_text)
            .block(Block::default().borders(Borders::ALL).title("📦 Repository"))
            .alignment(Alignment::Left);

        f.render_widget(system_info, chunks[3]);
    }

    /// Render left panel with metrics and charts
    fn render_left_panel<B: Backend>(&self, f: &mut Frame<B>, area: Rect, animation: &AnimationState) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(50), // Metrics chart
                Constraint::Percentage(50), // Activity log
            ])
            .split(area);

        // Metrics chart
        self.render_metrics_chart(f, chunks[0], animation);
        
        // Activity log
        self.render_activity_log(f, chunks[1]);
    }

    /// Render metrics chart
    fn render_metrics_chart<B: Backend>(&self, f: &mut Frame<B>, area: Rect, _animation: &AnimationState) {
        if self.metrics_history.is_empty() {
            let placeholder = Paragraph::new("Collecting metrics...")
                .block(Block::default().borders(Borders::ALL).title("📊 Metrics"))
                .alignment(Alignment::Center);
            f.render_widget(placeholder, area);
            return;
        }

        // Prepare sparkline data
        let data: Vec<u64> = self.metrics_history
            .iter()
            .rev()
            .take(20)
            .map(|m| m.secrets_count as u64)
            .collect();

        let sparkline = Sparkline::default()
            .block(Block::default().borders(Borders::ALL).title("📊 Secrets Over Time"))
            .data(&data)
            .style(CargoStyle::accent());

        f.render_widget(sparkline, area);
    }

    /// Render activity log
    fn render_activity_log<B: Backend>(&self, f: &mut Frame<B>) {
        let items: Vec<ListItem> = self.recent_activity
            .iter()
            .take(10)
            .map(|activity| {
                let elapsed = activity.timestamp.elapsed();
                let time_str = if elapsed.as_secs() < 60 {
                    format!("{}s ago", elapsed.as_secs())
                } else {
                    format!("{}m ago", elapsed.as_secs() / 60)
                };

                let icon = match activity.severity {
                    ActivitySeverity::Info => "ℹ️",
                    ActivitySeverity::Warning => "⚠️",
                    ActivitySeverity::Error => "❌",
                    ActivitySeverity::Success => "✅",
                };

                let style = match activity.severity {
                    ActivitySeverity::Info => CargoStyle::default(),
                    ActivitySeverity::Warning => CargoStyle::warning(),
                    ActivitySeverity::Error => CargoStyle::error(),
                    ActivitySeverity::Success => CargoStyle::success(),
                };

                ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(icon, style),
                        Span::raw(" "),
                        Span::styled(&activity.action, style),
                        Span::raw(" "),
                        Span::styled(&time_str, Style::default().fg(Color::Gray)),
                    ]),
                    Line::from(vec![
                        Span::raw("   "),
                        Span::styled(&activity.details, Style::default().fg(Color::Gray)),
                    ]),
                ])
            })
            .collect();

        let activity_list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("📋 Recent Activity"))
            .style(CargoStyle::default());

        f.render_widget(activity_list, area);
    }

    /// Render right panel with system info
    fn render_right_panel<B: Backend>(&self, f: &mut Frame<B>, area: Rect, animation: &AnimationState) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(50), // System info
                Constraint::Percentage(50), // Performance
            ])
            .split(area);

        // System info
        self.render_system_info(f, chunks[0], animation);
        
        // Performance info
        self.render_performance_info(f, chunks[1]);
    }

    /// Render system information
    fn render_system_info<B: Backend>(&self, f: &mut Frame<B>, area: Rect, animation: &AnimationState) {
        // Animated pulse for active status
        let pulse_intensity = (animation.pulse_phase.sin() + 1.0) / 2.0;
        let pulse_color = Color::Rgb(
            (255.0 * pulse_intensity) as u8,
            (100.0 + 155.0 * pulse_intensity) as u8,
            (50.0 + 205.0 * pulse_intensity) as u8,
        );

        let network_icon = match self.system_status.network_status {
            NetworkStatus::Connected => "🌐",
            NetworkStatus::Disconnected => "🔴",
            NetworkStatus::Limited => "🟡",
        };

        let uptime_str = format!("{}h {}m", 
            self.system_status.uptime.as_secs() / 3600,
            (self.system_status.uptime.as_secs() % 3600) / 60
        );

        let system_text = vec![
            Line::from(vec![
                Span::styled("Status: ", Style::default().fg(Color::Gray)),
                Span::styled("Online", Style::default().fg(pulse_color)),
            ]),
            Line::from(vec![
                Span::styled("Uptime: ", Style::default().fg(Color::Gray)),
                Span::styled(&uptime_str, CargoStyle::default()),
            ]),
            Line::from(vec![
                Span::styled("Network: ", Style::default().fg(Color::Gray)),
                Span::raw(network_icon),
                Span::raw(" "),
                Span::styled("Connected", CargoStyle::success()),
            ]),
            Line::from(vec![
                Span::styled("Memory: ", Style::default().fg(Color::Gray)),
                Span::styled("64MB", CargoStyle::default()),
            ]),
        ];

        let system_info = Paragraph::new(system_text)
            .block(Block::default().borders(Borders::ALL).title("💻 System"))
            .alignment(Alignment::Left);

        f.render_widget(system_info, area);
    }

    /// Render performance information
    fn render_performance_info<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let perf_text = vec![
            Line::from(vec![
                Span::styled("Files Scanned: ", Style::default().fg(Color::Gray)),
                Span::styled(self.quick_stats.files_scanned.to_string(), CargoStyle::highlight()),
            ]),
            Line::from(vec![
                Span::styled("Secrets Found: ", Style::default().fg(Color::Gray)),
                Span::styled(self.quick_stats.secrets_found.to_string(), CargoStyle::warning()),
            ]),
            Line::from(vec![
                Span::styled("False Positives: ", Style::default().fg(Color::Gray)),
                Span::styled(self.quick_stats.false_positives.to_string(), CargoStyle::default()),
            ]),
            Line::from(vec![
                Span::styled("Coverage: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{:.1}%", self.quick_stats.scan_coverage * 100.0), CargoStyle::success()),
            ]),
        ];

        let perf_info = Paragraph::new(perf_text)
            .block(Block::default().borders(Borders::ALL).title("⚡ Performance"))
            .alignment(Alignment::Left);

        f.render_widget(perf_info, area);
    }

    /// Get style for risk level
    fn risk_level_style(&self) -> Style {
        match self.security_overview.risk_level {
            RiskLevel::Low => CargoStyle::success(),
            RiskLevel::Medium => CargoStyle::warning(),
            RiskLevel::High => CargoStyle::error(),
            RiskLevel::Critical => Style::default().fg(Color::Rgb(255, 0, 0)).add_modifier(Modifier::BOLD),
        }
    }
}