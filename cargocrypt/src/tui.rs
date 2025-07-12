//! Simple TUI module for CargoCrypt
//!
//! Provides a basic terminal user interface for all CargoCrypt operations.

use crate::{CargoCrypt, CryptoResult};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::{
    io,
    sync::Arc,
    time::Duration,
};

/// Main menu options
#[derive(Debug, Clone, Copy, PartialEq)]
enum MenuOption {
    Initialize,
    EncryptFile,
    DecryptFile,
    ShowConfig,
    Exit,
}

impl MenuOption {
    fn all() -> Vec<Self> {
        vec![
            Self::Initialize,
            Self::EncryptFile,
            Self::DecryptFile,
            Self::ShowConfig,
            Self::Exit,
        ]
    }

    fn label(&self) -> &str {
        match self {
            Self::Initialize => "Initialize CargoCrypt",
            Self::EncryptFile => "Encrypt a file",
            Self::DecryptFile => "Decrypt a file",
            Self::ShowConfig => "Show configuration",
            Self::Exit => "Exit",
        }
    }

    fn description(&self) -> &str {
        match self {
            Self::Initialize => "Set up CargoCrypt in the current project",
            Self::EncryptFile => "Encrypt a file with password protection",
            Self::DecryptFile => "Decrypt an encrypted file",
            Self::ShowConfig => "View current CargoCrypt configuration",
            Self::Exit => "Exit the application",
        }
    }
}

/// TUI application state
struct App {
    selected_index: usize,
    menu_items: Vec<MenuOption>,
    status_message: String,
    should_quit: bool,
}

impl App {
    fn new() -> Self {
        Self {
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
        match self.get_selected() {
            MenuOption::Initialize => {
                match CargoCrypt::init_project().await {
                    Ok(_) => self.status_message = "✅ CargoCrypt initialized successfully!".to_string(),
                    Err(e) => self.status_message = format!("❌ Error: {}", e),
                }
            }
            MenuOption::EncryptFile => {
                self.status_message = "🔒 File encryption not yet implemented in TUI".to_string();
                // TODO: Implement file selection dialog
            }
            MenuOption::DecryptFile => {
                self.status_message = "🔓 File decryption not yet implemented in TUI".to_string();
                // TODO: Implement file selection dialog
            }
            MenuOption::ShowConfig => {
                let config = crypt.config().await;
                self.status_message = format!(
                    "📋 Config: Profile={:?}, Memory={}KiB, Time={}, Parallelism={}",
                    config.performance_profile,
                    config.key_params.memory_cost,
                    config.key_params.time_cost,
                    config.key_params.parallelism
                );
            }
            MenuOption::Exit => {
                self.should_quit = true;
            }
        }
        Ok(())
    }
}

fn ui(app: &App, frame: &mut Frame) {
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
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Up => app.previous(),
                    KeyCode::Down => app.next(),
                    KeyCode::Enter => {
                        app.handle_selection(&crypt).await?;
                        if app.should_quit {
                            break;
                        }
                    }
                    _ => {}
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