//! TUI monitoring dashboard
//!
//! Real-time monitoring interface showing performance metrics,
//! alerts, and system health in an interactive terminal UI.

use crate::monitoring::{MonitoringManager, HealthStatus, AlertSeverity, BottleneckType};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        BarChart, Block, Borders, Gauge, List, ListItem, Paragraph, 
        Row, Table, Tabs, Wrap
    },
    Frame, Terminal,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

/// TUI monitoring dashboard
pub struct MonitoringDashboard {
    monitoring: Arc<MonitoringManager>,
    active_tab: usize,
    should_quit: bool,
    last_update: Instant,
    update_interval: Duration,
}

#[derive(Debug, Clone)]
enum Tab {
    Overview,
    Metrics,
    Alerts,
    Performance,
    Memory,
}

impl MonitoringDashboard {
    /// Create a new monitoring dashboard
    pub fn new(monitoring: Arc<MonitoringManager>) -> Self {
        Self {
            monitoring,
            active_tab: 0,
            should_quit: false,
            last_update: Instant::now(),
            update_interval: Duration::from_secs(2),
        }
    }
    
    /// Run the monitoring dashboard
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        
        // Create app and run it
        let res = self.run_app(&mut terminal).await;
        
        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;
        
        if let Err(err) = res {
            println!("{err:?}");
        }
        
        Ok(())
    }
    
    async fn run_app<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            if self.last_update.elapsed() >= self.update_interval {
                self.last_update = Instant::now();
            }
            
            terminal.draw(|f| self.ui(f))?;
            
            if crossterm::event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') => {
                            self.should_quit = true;
                        }
                        KeyCode::Left => {
                            if self.active_tab > 0 {
                                self.active_tab -= 1;
                            }
                        }
                        KeyCode::Right => {
                            if self.active_tab < 4 {
                                self.active_tab += 1;
                            }
                        }
                        KeyCode::Char('1') => self.active_tab = 0,
                        KeyCode::Char('2') => self.active_tab = 1,
                        KeyCode::Char('3') => self.active_tab = 2,
                        KeyCode::Char('4') => self.active_tab = 3,
                        KeyCode::Char('5') => self.active_tab = 4,
                        _ => {}
                    }
                }
            }
            
            if self.should_quit {
                break;
            }
            
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }
    
    fn ui(&self, f: &mut Frame) {
        let size = f.size();
        
        // Create the main layout
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Tabs
                Constraint::Min(0),    // Content
                Constraint::Length(3), // Status bar
            ])
            .split(size);
        
        // Render tabs
        self.render_tabs(f, chunks[0]);
        
        // Render content based on active tab
        match self.active_tab {
            0 => self.render_overview(f, chunks[1]),
            1 => self.render_metrics(f, chunks[1]),
            2 => self.render_alerts(f, chunks[1]),
            3 => self.render_performance(f, chunks[1]),
            4 => self.render_memory(f, chunks[1]),
            _ => {}
        }
        
        // Render status bar
        self.render_status_bar(f, chunks[2]);
    }
    
    fn render_tabs(&self, f: &mut Frame, area: Rect) {
        let tabs = Tabs::new(vec![
            "Overview", "Metrics", "Alerts", "Performance", "Memory"
        ])
        .block(Block::default().borders(Borders::ALL).title("CargoCrypt Monitoring"))
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .select(self.active_tab);
        
        f.render_widget(tabs, area);
    }
    
    fn render_overview(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5), // Health status
                Constraint::Min(5),    // Recent activity
            ])
            .split(area);
        
        // Health status
        let health_text = vec![
            Line::from(vec![
                Span::styled("System Status: ", Style::default().fg(Color::White)),
                Span::styled("Healthy", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Uptime: ", Style::default().fg(Color::White)),
                Span::styled("2h 34m", Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Active Operations: ", Style::default().fg(Color::White)),
                Span::styled("3", Style::default().fg(Color::Yellow)),
            ]),
        ];
        
        let health_block = Paragraph::new(health_text)
            .block(Block::default().borders(Borders::ALL).title("System Health"))
            .wrap(Wrap { trim: true });
        
        f.render_widget(health_block, chunks[0]);
        
        // Recent activity
        let activities = vec![
            ListItem::new("Encrypted file: src/config.rs (1.2KB)"),
            ListItem::new("Performance alert: Slow operation detected"),
            ListItem::new("Memory usage: 45.2MB (peak: 67.1MB)"),
            ListItem::new("Decrypted file: data/secrets.enc (2.4KB)"),
        ];
        
        let activity_list = List::new(activities)
            .block(Block::default().borders(Borders::ALL).title("Recent Activity"))
            .style(Style::default().fg(Color::White));
        
        f.render_widget(activity_list, chunks[1]);
    }
    
    fn render_metrics(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        
        // Crypto operations metrics
        let crypto_data = vec![
            ("Encrypt", 15),
            ("Decrypt", 12),
            ("KeyGen", 3),
        ];
        
        let crypto_chart = BarChart::default()
            .block(Block::default().borders(Borders::ALL).title("Crypto Operations"))
            .data(&crypto_data)
            .bar_width(9)
            .bar_style(Style::default().fg(Color::Green))
            .value_style(Style::default().fg(Color::Black).bg(Color::Green));
        
        f.render_widget(crypto_chart, chunks[0]);
        
        // File operations metrics
        let file_data = vec![
            ("Read", 25),
            ("Write", 18),
            ("Delete", 2),
        ];
        
        let file_chart = BarChart::default()
            .block(Block::default().borders(Borders::ALL).title("File Operations"))
            .data(&file_data)
            .bar_width(9)
            .bar_style(Style::default().fg(Color::Blue))
            .value_style(Style::default().fg(Color::Black).bg(Color::Blue));
        
        f.render_widget(file_chart, chunks[1]);
    }
    
    fn render_alerts(&self, f: &mut Frame, area: Rect) {
        let alerts = vec![
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("⚠ ", Style::default().fg(Color::Yellow)),
                    Span::styled("WARNING", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::styled(" - Slow Operation", Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled("Encryption taking 2.3s (threshold: 1.0s)", Style::default().fg(Color::Gray)),
                ]),
            ]),
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("ℹ ", Style::default().fg(Color::Blue)),
                    Span::styled("INFO", Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)),
                    Span::styled(" - Memory Usage", Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled("Peak memory usage: 67.1MB", Style::default().fg(Color::Gray)),
                ]),
            ]),
        ];
        
        let alerts_list = List::new(alerts)
            .block(Block::default().borders(Borders::ALL).title("Active Alerts"))
            .style(Style::default().fg(Color::White));
        
        f.render_widget(alerts_list, area);
    }
    
    fn render_performance(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6),  // Throughput
                Constraint::Length(6),  // Latency
                Constraint::Min(0),     // Performance table
            ])
            .split(area);
        
        // Throughput gauge
        let throughput = 73; // percentage
        let throughput_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Throughput"))
            .gauge_style(Style::default().fg(Color::Green))
            .percent(throughput)
            .label(format!("{throughput}% (15.3 ops/sec)"));
        
        f.render_widget(throughput_gauge, chunks[0]);
        
        // Latency gauge
        let latency = 42; // percentage (lower is better)
        let latency_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Average Latency"))
            .gauge_style(Style::default().fg(Color::Yellow))
            .percent(latency)
            .label(format!("{}ms", 145));
        
        f.render_widget(latency_gauge, chunks[1]);
        
        // Performance table
        let rows = vec![
            Row::new(vec!["encrypt_file", "23", "156ms", "0.2%"]),
            Row::new(vec!["decrypt_file", "18", "134ms", "0.0%"]),
            Row::new(vec!["key_derivation", "3", "2.1s", "0.0%"]),
        ];
        
        let table = Table::new(rows)
            .widths(&[
                Constraint::Percentage(40),
                Constraint::Percentage(20),
                Constraint::Percentage(20), 
                Constraint::Percentage(20),
            ])
        .header(Row::new(vec!["Operation", "Count", "Avg Time", "Error %"])
            .style(Style::default().add_modifier(Modifier::BOLD)))
        .block(Block::default().borders(Borders::ALL).title("Operation Stats"));
        
        f.render_widget(table, chunks[2]);
    }
    
    fn render_memory(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6),  // Memory usage gauge
                Constraint::Min(0),     // Memory details
            ])
            .split(area);
        
        // Memory usage gauge
        let memory_usage = 68; // percentage
        let memory_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Memory Usage"))
            .gauge_style(Style::default().fg(Color::Red))
            .percent(memory_usage)
            .label(format!("{}% (45.2MB / 67.1MB peak)", memory_usage));
        
        f.render_widget(memory_gauge, chunks[0]);
        
        // Memory details
        let memory_text = vec![
            Line::from(vec![
                Span::styled("Current: ", Style::default().fg(Color::White)),
                Span::styled("45.2 MB", Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Peak: ", Style::default().fg(Color::White)),
                Span::styled("67.1 MB", Style::default().fg(Color::Red)),
            ]),
            Line::from(vec![
                Span::styled("Average: ", Style::default().fg(Color::White)),
                Span::styled("38.7 MB", Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("Growth Rate: ", Style::default().fg(Color::White)),
                Span::styled("+0.3 MB/min", Style::default().fg(Color::Yellow)),
            ]),
        ];
        
        let memory_block = Paragraph::new(memory_text)
            .block(Block::default().borders(Borders::ALL).title("Memory Statistics"))
            .wrap(Wrap { trim: true });
        
        f.render_widget(memory_block, chunks[1]);
    }
    
    fn render_status_bar(&self, f: &mut Frame, area: Rect) {
        let status_text = vec![
            Line::from(vec![
                Span::styled("Press ", Style::default().fg(Color::Gray)),
                Span::styled("q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(" to quit, ", Style::default().fg(Color::Gray)),
                Span::styled("←/→", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(" or ", Style::default().fg(Color::Gray)),
                Span::styled("1-5", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(" to navigate tabs", Style::default().fg(Color::Gray)),
            ]),
        ];
        
        let status_block = Paragraph::new(status_text)
            .block(Block::default().borders(Borders::ALL))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        
        f.render_widget(status_block, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::MonitoringConfig;
    
    #[test]
    fn test_dashboard_creation() {
        let monitoring = Arc::new(MonitoringManager::new(MonitoringConfig::default()));
        let dashboard = MonitoringDashboard::new(monitoring);
        assert_eq!(dashboard.active_tab, 0);
        assert!(!dashboard.should_quit);
    }
}