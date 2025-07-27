//! Simplified TUI implementation for CargoCrypt file browser

use crate::{CargoCrypt, CryptoResult};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Alignment},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, ListState},
    Frame, Terminal,
};
use std::{
    io,
    sync::Arc,
    path::PathBuf,
    fs::{self, DirEntry},
    collections::HashSet,
    time::Duration,
};

/// Main TUI application
pub struct TuiApp {
    current_path: PathBuf,
    files: Vec<FileInfo>,
    selected_index: usize,
    selected_files: HashSet<PathBuf>,
    list_state: ListState,
    status_message: String,
    should_quit: bool,
}

/// File information for display
#[derive(Clone)]
struct FileInfo {
    path: PathBuf,
    name: String,
    is_directory: bool,
    is_encrypted: bool,
    is_selected: bool,
}

impl TuiApp {
    pub fn new() -> CryptoResult<Self> {
        let current_path = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut app = Self {
            current_path,
            files: Vec::new(),
            selected_index: 0,
            selected_files: HashSet::new(),
            list_state: ListState::default(),
            status_message: "CargoCrypt File Browser - Press 'q' to quit".to_string(),
            should_quit: false,
        };
        app.refresh_files()?;
        Ok(app)
    }

    /// Refresh the file list for current directory
    fn refresh_files(&mut self) -> CryptoResult<()> {
        self.files.clear();
        
        // Add parent directory entry
        if self.current_path.parent().is_some() {
            self.files.push(FileInfo {
                path: self.current_path.join(".."),
                name: "..".to_string(),
                is_directory: true,
                is_encrypted: false,
                is_selected: false,
            });
        }

        // Read directory entries
        let entries = fs::read_dir(&self.current_path)
            .map_err(|e| crate::error::CargoCryptError::from(e))?;

        for entry in entries {
            let entry = entry.map_err(|e| crate::error::CargoCryptError::from(e))?;
            let path = entry.path();
            
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<invalid>")
                .to_string();
            
            let is_directory = path.is_dir();
            let is_encrypted = path.extension()
                .and_then(|e| e.to_str())
                .map(|ext| ext == "enc")
                .unwrap_or(false);
            let is_selected = self.selected_files.contains(&path);

            self.files.push(FileInfo {
                path,
                name,
                is_directory,
                is_encrypted,
                is_selected,
            });
        }

        // Sort: directories first, then files
        self.files.sort_by(|a, b| {
            match (a.is_directory, b.is_directory) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            }
        });

        self.selected_index = 0;
        self.update_list_state();
        Ok(())
    }

    /// Update list state for proper selection display
    fn update_list_state(&mut self) {
        self.list_state.select(Some(self.selected_index));
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
    fn get_selected_file(&self) -> Option<&FileInfo> {
        self.files.get(self.selected_index)
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

    /// Handle key events
    async fn handle_key(&mut self, key: KeyCode, crypt: &Arc<CargoCrypt>) -> CryptoResult<()> {
        match key {
            // Navigation
            KeyCode::Up | KeyCode::Char('k') => self.move_up(),
            KeyCode::Down | KeyCode::Char('j') => self.move_down(),
            
            // Directory navigation
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if let Some(file) = self.get_selected_file() {
                    if file.is_directory {
                        if file.name == ".." {
                            if let Some(parent) = self.current_path.parent() {
                                let _ = self.navigate_to(parent.to_path_buf());
                            }
                        } else {
                            let _ = self.navigate_to(file.path.clone());
                        }
                    }
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if let Some(parent) = self.current_path.parent() {
                    let _ = self.navigate_to(parent.to_path_buf());
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
                self.toggle_selection();
            }
            
            // Refresh
            KeyCode::Char('r') => {
                let _ = self.refresh_files();
                self.status_message = "Directory refreshed".to_string();
            }
            
            // Quit
            KeyCode::Char('q') | KeyCode::Esc => {
                self.should_quit = true;
            }
            
            _ => {}
        }
        Ok(())
    }

    /// Encrypt selected files
    async fn encrypt_selected_files(&mut self, crypt: &Arc<CargoCrypt>) -> CryptoResult<()> {
        let files_to_encrypt: Vec<PathBuf> = if self.selected_files.is_empty() {
            if let Some(file) = self.get_selected_file() {
                if !file.is_directory && !file.is_encrypted {
                    vec![file.path.clone()]
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            self.selected_files.iter()
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

        let mut encrypted_count = 0;
        for file_path in &files_to_encrypt {
            // For demo purposes, use a default password
            let password = "demo_password";
            
            match crypt.encrypt_file(file_path, password).await {
                Ok(_) => {
                    encrypted_count += 1;
                }
                Err(e) => {
                    self.status_message = format!("Error encrypting {}: {}", file_path.display(), e);
                    break;
                }
            }
        }
        
        self.selected_files.clear();
        let _ = self.refresh_files();
        
        if encrypted_count > 0 {
            self.status_message = format!("Encrypted {} files", encrypted_count);
        }
        Ok(())
    }

    /// Decrypt selected files
    async fn decrypt_selected_files(&mut self, crypt: &Arc<CargoCrypt>) -> CryptoResult<()> {
        let files_to_decrypt: Vec<PathBuf> = if self.selected_files.is_empty() {
            if let Some(file) = self.get_selected_file() {
                if !file.is_directory && file.is_encrypted {
                    vec![file.path.clone()]
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            self.selected_files.iter()
                .filter(|path| path.extension().and_then(|e| e.to_str()).map(|ext| ext == "enc").unwrap_or(false))
                .cloned()
                .collect()
        };

        if files_to_decrypt.is_empty() {
            self.status_message = "No encrypted files to decrypt".to_string();
            return Ok(());
        }

        let mut decrypted_count = 0;
        for file_path in &files_to_decrypt {
            let password = "demo_password";
            
            match crypt.decrypt_file(file_path, password).await {
                Ok(_) => {
                    decrypted_count += 1;
                }
                Err(e) => {
                    self.status_message = format!("Error decrypting {}: {}", file_path.display(), e);
                    break;
                }
            }
        }
        
        self.selected_files.clear();
        let _ = self.refresh_files();
        
        if decrypted_count > 0 {
            self.status_message = format!("Decrypted {} files", decrypted_count);
        }
        Ok(())
    }
}

/// Render the TUI
fn render_ui(app: &TuiApp, frame: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),      // Header
            Constraint::Min(5),         // File list
            Constraint::Length(3),      // Status
            Constraint::Length(2),      // Help
        ])
        .split(frame.size());

    // Header
    let header = Paragraph::new(format!("CargoCrypt File Browser - {}", app.current_path.display()))
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL).title("Directory"));
    frame.render_widget(header, chunks[0]);

    // File list
    let items: Vec<ListItem> = app.files
        .iter()
        .enumerate()
        .map(|(i, file)| {
            let mut indicators = Vec::new();
            
            if file.is_directory {
                indicators.push("[DIR]");
            }
            if file.is_encrypted {
                indicators.push("[ENC]");
            }
            if file.is_selected {
                indicators.push("[SEL]");
            }
            
            let indicator_str = if indicators.is_empty() {
                String::new()
            } else {
                format!(" {}", indicators.join(" "))
            };
            
            let style = if i == app.selected_index {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else if file.is_selected {
                Style::default().bg(Color::DarkGray).fg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };
            
            let content = format!("{}{}", file.name, indicator_str);
            ListItem::new(Line::from(Span::styled(content, style)))
        })
        .collect();
    
    let mut list_state = app.list_state.clone();
    let file_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Files"))
        .highlight_style(Style::default().bg(Color::Blue));
    
    frame.render_stateful_widget(file_list, chunks[1], &mut list_state);

    // Status
    let status = Paragraph::new(app.status_message.as_str())
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(status, chunks[2]);

    // Help
    let help = Paragraph::new("j/k: Navigate | Enter: Open | Space: Select | e: Encrypt | d: Decrypt | r: Refresh | q: Quit")
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().borders(Borders::TOP));
    frame.render_widget(help, chunks[3]);
}

/// Run the simplified TUI application
pub async fn run_simple_tui(crypt: Arc<CargoCrypt>) -> CryptoResult<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = TuiApp::new()?;

    // Main loop
    loop {
        terminal.draw(|f| render_ui(&app, f))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key(key.code, &crypt).await?;
                
                if app.should_quit {
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