//! Secret management interface for CargoCrypt TUI
//!
//! Provides interactive secret browsing, searching, and management capabilities.

use ratatui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Wrap,
    },
    Frame,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    crypto::{EncryptedSecret, SecretMetadata, SecretType},
    detection::{Finding, FoundSecret},
    CargoCrypt, CryptoResult,
};

use super::{CargoStyle, CargoSymbols, NavigationState};

/// Secret management state
#[derive(Debug, Clone)]
pub struct SecretManager {
    /// CargoCrypt instance
    crypt: Option<Arc<CargoCrypt>>,
    /// List of discovered secrets
    secrets: Vec<ManagedSecret>,
    /// Currently selected secret
    selected_secret: Option<usize>,
    /// Search filter
    search_filter: String,
    /// Filtered secrets list
    filtered_secrets: Vec<usize>,
    /// Secret viewer state
    viewer_state: SecretViewerState,
    /// Last update time
    last_update: Instant,
    /// Secret categories
    categories: HashMap<SecretType, Vec<usize>>,
    /// Show encrypted secrets only
    show_encrypted_only: bool,
    /// Sort order
    sort_order: SortOrder,
}

/// Managed secret with metadata
#[derive(Debug, Clone)]
pub struct ManagedSecret {
    /// Secret ID
    pub id: String,
    /// Secret type
    pub secret_type: SecretType,
    /// File path where found
    pub file_path: String,
    /// Line number in file
    pub line_number: usize,
    /// Secret preview (masked)
    pub preview: String,
    /// Full secret content (encrypted)
    pub encrypted_content: Option<EncryptedSecret>,
    /// Metadata
    pub metadata: SecretMetadata,
    /// Is currently encrypted
    pub is_encrypted: bool,
    /// Risk level assessment
    pub risk_level: RiskLevel,
    /// Last accessed time
    pub last_accessed: Option<Instant>,
    /// Tags
    pub tags: Vec<String>,
    /// Notes
    pub notes: String,
}

/// Secret viewer state
#[derive(Debug, Clone)]
pub struct SecretViewerState {
    /// Currently viewing secret
    pub viewing: Option<usize>,
    /// Scroll position in viewer
    pub scroll_position: usize,
    /// Show full content (dangerous)
    pub show_full_content: bool,
    /// Viewer mode
    pub mode: ViewerMode,
}

/// Viewer modes
#[derive(Debug, Clone, PartialEq)]
pub enum ViewerMode {
    Preview,
    Metadata,
    Content,
    Edit,
}

/// Sort order for secrets
#[derive(Debug, Clone, PartialEq)]
pub enum SortOrder {
    Name,
    Type,
    Risk,
    LastAccessed,
    FileLocation,
}

/// Risk level for secrets
#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for SecretManager {
    fn default() -> Self {
        Self {
            crypt: None,
            secrets: Vec::new(),
            selected_secret: None,
            search_filter: String::new(),
            filtered_secrets: Vec::new(),
            viewer_state: SecretViewerState {
                viewing: None,
                scroll_position: 0,
                show_full_content: false,
                mode: ViewerMode::Preview,
            },
            last_update: Instant::now(),
            categories: HashMap::new(),
            show_encrypted_only: false,
            sort_order: SortOrder::Risk,
        }
    }
}

impl SecretManager {
    /// Initialize secret manager
    pub async fn init(&mut self, crypt: Arc<CargoCrypt>) -> CryptoResult<()> {
        self.crypt = Some(crypt);
        self.refresh().await?;
        Ok(())
    }

    /// Refresh secrets list
    pub async fn refresh(&mut self) -> CryptoResult<()> {
        if let Some(crypt) = &self.crypt {
            // Scan for secrets using the detection system
            self.scan_for_secrets(crypt).await?;
            
            // Update categories
            self.update_categories();
            
            // Apply current filter
            self.apply_filter();
            
            // Sort secrets
            self.sort_secrets();
            
            self.last_update = Instant::now();
        }
        
        Ok(())
    }

    /// Scan for secrets in the project
    async fn scan_for_secrets(&mut self, crypt: &Arc<CargoCrypt>) -> CryptoResult<()> {
        // This would integrate with the actual secret detection system
        // For now, we'll create some example secrets
        
        self.secrets.clear();
        
        // Example secrets for demonstration
        let example_secrets = vec![
            ManagedSecret {
                id: "secret_1".to_string(),
                secret_type: SecretType::ApiKey,
                file_path: "src/config.rs".to_string(),
                line_number: 42,
                preview: "sk-****************************".to_string(),
                encrypted_content: None,
                metadata: SecretMetadata {
                    created_at: Instant::now(),
                    last_modified: Instant::now(),
                    access_count: 5,
                    tags: vec!["api".to_string(), "openai".to_string()],
                },
                is_encrypted: false,
                risk_level: RiskLevel::High,
                last_accessed: Some(Instant::now()),
                tags: vec!["api".to_string(), "openai".to_string()],
                notes: "OpenAI API key found in config file".to_string(),
            },
            ManagedSecret {
                id: "secret_2".to_string(),
                secret_type: SecretType::DatabaseUrl,
                file_path: ".env".to_string(),
                line_number: 15,
                preview: "postgresql://user:****@localhost/db".to_string(),
                encrypted_content: None,
                metadata: SecretMetadata {
                    created_at: Instant::now(),
                    last_modified: Instant::now(),
                    access_count: 12,
                    tags: vec!["database".to_string(), "postgres".to_string()],
                },
                is_encrypted: true,
                risk_level: RiskLevel::Critical,
                last_accessed: Some(Instant::now()),
                tags: vec!["database".to_string(), "postgres".to_string()],
                notes: "Database connection string - encrypted".to_string(),
            },
            ManagedSecret {
                id: "secret_3".to_string(),
                secret_type: SecretType::PrivateKey,
                file_path: "keys/private.key".to_string(),
                line_number: 1,
                preview: "-----BEGIN RSA PRIVATE KEY-----".to_string(),
                encrypted_content: None,
                metadata: SecretMetadata {
                    created_at: Instant::now(),
                    last_modified: Instant::now(),
                    access_count: 2,
                    tags: vec!["rsa".to_string(), "crypto".to_string()],
                },
                is_encrypted: true,
                risk_level: RiskLevel::Critical,
                last_accessed: None,
                tags: vec!["rsa".to_string(), "crypto".to_string()],
                notes: "RSA private key - securely encrypted".to_string(),
            },
            ManagedSecret {
                id: "secret_4".to_string(),
                secret_type: SecretType::Password,
                file_path: "tests/test_data.rs".to_string(),
                line_number: 89,
                preview: "password: \"****\"".to_string(),
                encrypted_content: None,
                metadata: SecretMetadata {
                    created_at: Instant::now(),
                    last_modified: Instant::now(),
                    access_count: 1,
                    tags: vec!["test".to_string(), "password".to_string()],
                },
                is_encrypted: false,
                risk_level: RiskLevel::Medium,
                last_accessed: None,
                tags: vec!["test".to_string(), "password".to_string()],
                notes: "Test password - should be encrypted".to_string(),
            },
        ];
        
        self.secrets = example_secrets;
        
        Ok(())
    }

    /// Update secret categories
    fn update_categories(&mut self) {
        self.categories.clear();
        
        for (index, secret) in self.secrets.iter().enumerate() {
            self.categories
                .entry(secret.secret_type)
                .or_insert_with(Vec::new)
                .push(index);
        }
    }

    /// Apply search filter
    fn apply_filter(&mut self) {
        self.filtered_secrets.clear();
        
        for (index, secret) in self.secrets.iter().enumerate() {
            if self.matches_filter(secret) {
                self.filtered_secrets.push(index);
            }
        }
    }

    /// Check if secret matches current filter
    fn matches_filter(&self, secret: &ManagedSecret) -> bool {
        if self.show_encrypted_only && !secret.is_encrypted {
            return false;
        }
        
        if self.search_filter.is_empty() {
            return true;
        }
        
        let filter_lower = self.search_filter.to_lowercase();
        
        secret.file_path.to_lowercase().contains(&filter_lower)
            || secret.preview.to_lowercase().contains(&filter_lower)
            || secret.notes.to_lowercase().contains(&filter_lower)
            || secret.tags.iter().any(|tag| tag.to_lowercase().contains(&filter_lower))
    }

    /// Sort secrets by current order
    fn sort_secrets(&mut self) {
        self.filtered_secrets.sort_by(|&a, &b| {
            let secret_a = &self.secrets[a];
            let secret_b = &self.secrets[b];
            
            match self.sort_order {
                SortOrder::Name => secret_a.file_path.cmp(&secret_b.file_path),
                SortOrder::Type => secret_a.secret_type.cmp(&secret_b.secret_type),
                SortOrder::Risk => secret_b.risk_level.cmp(&secret_a.risk_level),
                SortOrder::LastAccessed => {
                    match (secret_a.last_accessed, secret_b.last_accessed) {
                        (Some(a), Some(b)) => b.cmp(&a),
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (None, None) => std::cmp::Ordering::Equal,
                    }
                }
                SortOrder::FileLocation => {
                    let cmp = secret_a.file_path.cmp(&secret_b.file_path);
                    if cmp == std::cmp::Ordering::Equal {
                        secret_a.line_number.cmp(&secret_b.line_number)
                    } else {
                        cmp
                    }
                }
            }
        });
    }

    /// Search for secrets
    pub async fn search(&mut self, query: &str) -> CryptoResult<()> {
        self.search_filter = query.to_string();
        self.apply_filter();
        self.sort_secrets();
        Ok(())
    }

    /// Get secret count
    pub async fn count(&self) -> usize {
        self.secrets.len()
    }

    /// Activate selected secret
    pub async fn activate_selected(&mut self, index: usize) -> CryptoResult<()> {
        if index < self.filtered_secrets.len() {
            let secret_index = self.filtered_secrets[index];
            self.viewer_state.viewing = Some(secret_index);
            self.viewer_state.mode = ViewerMode::Preview;
            self.viewer_state.scroll_position = 0;
            
            // Update last accessed time
            if let Some(secret) = self.secrets.get_mut(secret_index) {
                secret.last_accessed = Some(Instant::now());
                secret.metadata.access_count += 1;
            }
        }
        Ok(())
    }

    /// Toggle encryption for selected secret
    pub async fn toggle_selected(&mut self, index: usize) -> CryptoResult<()> {
        if index < self.filtered_secrets.len() {
            let secret_index = self.filtered_secrets[index];
            
            if let Some(secret) = self.secrets.get_mut(secret_index) {
                if let Some(crypt) = &self.crypt {
                    if secret.is_encrypted {
                        // Decrypt secret
                        // This would integrate with the actual decryption system
                        secret.is_encrypted = false;
                        secret.notes = format!("{} - DECRYPTED", secret.notes);
                    } else {
                        // Encrypt secret
                        // This would integrate with the actual encryption system
                        secret.is_encrypted = true;
                        secret.notes = format!("{} - ENCRYPTED", secret.notes);
                    }
                }
            }
        }
        Ok(())
    }

    /// Get selected secret for clipboard
    pub async fn get_selected(&self, index: usize) -> CryptoResult<Option<String>> {
        if index < self.filtered_secrets.len() {
            let secret_index = self.filtered_secrets[index];
            if let Some(secret) = self.secrets.get(secret_index) {
                // Return preview for clipboard (never full content for security)
                return Ok(Some(secret.preview.clone()));
            }
        }
        Ok(None)
    }

    /// Save secrets (if modified)
    pub async fn save(&mut self) -> CryptoResult<()> {
        // This would integrate with persistent storage
        self.last_update = Instant::now();
        Ok(())
    }

    /// Render secrets interface
    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect, nav_state: &NavigationState) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(40), // Secrets list
                Constraint::Percentage(60), // Details/viewer
            ])
            .split(area);

        self.render_secrets_list(f, chunks[0], nav_state);
        self.render_secret_details(f, chunks[1]);
    }

    /// Render secrets list
    fn render_secrets_list<B: Backend>(&self, f: &mut Frame<B>, area: Rect, nav_state: &NavigationState) {
        let items: Vec<ListItem> = self.filtered_secrets
            .iter()
            .map(|&index| {
                let secret = &self.secrets[index];
                
                let risk_icon = match secret.risk_level {
                    RiskLevel::Low => "🟢",
                    RiskLevel::Medium => "🟡",
                    RiskLevel::High => "🟠",
                    RiskLevel::Critical => "🔴",
                };
                
                let encryption_icon = if secret.is_encrypted {
                    CargoSymbols::LOCK
                } else {
                    CargoSymbols::UNLOCK
                };
                
                let type_icon = match secret.secret_type {
                    SecretType::ApiKey => "🔑",
                    SecretType::DatabaseUrl => "🗄️",
                    SecretType::PrivateKey => "🔐",
                    SecretType::Password => "🔒",
                    _ => "🔍",
                };
                
                ListItem::new(vec![
                    Line::from(vec![
                        Span::raw(risk_icon),
                        Span::raw(" "),
                        Span::raw(encryption_icon),
                        Span::raw(" "),
                        Span::raw(type_icon),
                        Span::raw(" "),
                        Span::styled(&secret.file_path, CargoStyle::highlight()),
                        Span::styled(format!(":{}", secret.line_number), CargoStyle::muted()),
                    ]),
                    Line::from(vec![
                        Span::raw("   "),
                        Span::styled(&secret.preview, CargoStyle::default()),
                    ]),
                    Line::from(vec![
                        Span::raw("   "),
                        Span::styled(&secret.notes, CargoStyle::muted()),
                    ]),
                ])
            })
            .collect();

        let title = format!("🔐 Secrets ({}/{})", 
            self.filtered_secrets.len(), 
            self.secrets.len()
        );

        let mut list_state = nav_state.list_state.clone();
        let secrets_list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .style(CargoStyle::default())
            .highlight_style(CargoStyle::selected());

        f.render_stateful_widget(secrets_list, area, &mut list_state);

        // Render scrollbar
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));

        let mut scrollbar_state = nav_state.scrollbar_state.clone();
        f.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
    }

    /// Render secret details/viewer
    fn render_secret_details<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        if let Some(viewing_index) = self.viewer_state.viewing {
            if let Some(secret) = self.secrets.get(viewing_index) {
                self.render_secret_viewer(f, area, secret);
            } else {
                self.render_no_selection(f, area);
            }
        } else {
            self.render_no_selection(f, area);
        }
    }

    /// Render individual secret viewer
    fn render_secret_viewer<B: Backend>(&self, f: &mut Frame<B>, area: Rect, secret: &ManagedSecret) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),  // Header
                Constraint::Min(0),     // Content
                Constraint::Length(3),  // Actions
            ])
            .split(area);

        // Header
        self.render_secret_header(f, chunks[0], secret);
        
        // Content based on viewer mode
        match self.viewer_state.mode {
            ViewerMode::Preview => self.render_secret_preview(f, chunks[1], secret),
            ViewerMode::Metadata => self.render_secret_metadata(f, chunks[1], secret),
            ViewerMode::Content => self.render_secret_content(f, chunks[1], secret),
            ViewerMode::Edit => self.render_secret_editor(f, chunks[1], secret),
        }
        
        // Actions
        self.render_secret_actions(f, chunks[2], secret);
    }

    /// Render secret header
    fn render_secret_header<B: Backend>(&self, f: &mut Frame<B>, area: Rect, secret: &ManagedSecret) {
        let risk_style = match secret.risk_level {
            RiskLevel::Low => CargoStyle::success(),
            RiskLevel::Medium => CargoStyle::warning(),
            RiskLevel::High => CargoStyle::error(),
            RiskLevel::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD | Modifier::BLINK),
        };
        
        let header_text = vec![
            Line::from(vec![
                Span::styled("Type: ", CargoStyle::muted()),
                Span::styled(format!("{:?}", secret.secret_type), CargoStyle::highlight()),
                Span::raw("  "),
                Span::styled("Risk: ", CargoStyle::muted()),
                Span::styled(format!("{:?}", secret.risk_level), risk_style),
            ]),
            Line::from(vec![
                Span::styled("File: ", CargoStyle::muted()),
                Span::styled(&secret.file_path, CargoStyle::default()),
                Span::styled(format!(":{}", secret.line_number), CargoStyle::muted()),
            ]),
            Line::from(vec![
                Span::styled("Encrypted: ", CargoStyle::muted()),
                Span::styled(if secret.is_encrypted { "Yes" } else { "No" }, 
                    if secret.is_encrypted { CargoStyle::success() } else { CargoStyle::error() }),
                Span::raw("  "),
                Span::styled("Accessed: ", CargoStyle::muted()),
                Span::styled(format!("{} times", secret.metadata.access_count), CargoStyle::default()),
            ]),
            Line::from(vec![
                Span::styled("Tags: ", CargoStyle::muted()),
                Span::styled(secret.tags.join(", "), CargoStyle::accent()),
            ]),
        ];
        
        let header = Paragraph::new(header_text)
            .block(Block::default().borders(Borders::ALL).title("Secret Details"))
            .alignment(Alignment::Left);
        
        f.render_widget(header, area);
    }

    /// Render secret preview
    fn render_secret_preview<B: Backend>(&self, f: &mut Frame<B>, area: Rect, secret: &ManagedSecret) {
        let preview_text = if secret.is_encrypted {
            "🔒 This secret is encrypted and cannot be previewed.\nUse the decrypt function to view contents."
        } else {
            "⚠️ WARNING: This secret is not encrypted!\nConsider encrypting it for better security."
        };
        
        let preview = Paragraph::new(preview_text)
            .block(Block::default().borders(Borders::ALL).title("Preview"))
            .style(if secret.is_encrypted { CargoStyle::success() } else { CargoStyle::error() })
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        
        f.render_widget(preview, area);
    }

    /// Render secret metadata
    fn render_secret_metadata<B: Backend>(&self, f: &mut Frame<B>, area: Rect, secret: &ManagedSecret) {
        let last_accessed = if let Some(accessed) = secret.last_accessed {
            format!("{:.2}s ago", accessed.elapsed().as_secs_f64())
        } else {
            "Never".to_string()
        };
        
        let metadata_text = vec![
            Line::from(vec![
                Span::styled("Created: ", CargoStyle::muted()),
                Span::styled(format!("{:.2}s ago", secret.metadata.created_at.elapsed().as_secs_f64()), CargoStyle::default()),
            ]),
            Line::from(vec![
                Span::styled("Modified: ", CargoStyle::muted()),
                Span::styled(format!("{:.2}s ago", secret.metadata.last_modified.elapsed().as_secs_f64()), CargoStyle::default()),
            ]),
            Line::from(vec![
                Span::styled("Last Accessed: ", CargoStyle::muted()),
                Span::styled(&last_accessed, CargoStyle::default()),
            ]),
            Line::from(vec![
                Span::styled("Access Count: ", CargoStyle::muted()),
                Span::styled(secret.metadata.access_count.to_string(), CargoStyle::highlight()),
            ]),
            Line::from(vec![
                Span::styled("ID: ", CargoStyle::muted()),
                Span::styled(&secret.id, CargoStyle::code()),
            ]),
        ];
        
        let metadata = Paragraph::new(metadata_text)
            .block(Block::default().borders(Borders::ALL).title("Metadata"))
            .alignment(Alignment::Left);
        
        f.render_widget(metadata, area);
    }

    /// Render secret content (dangerous!)
    fn render_secret_content<B: Backend>(&self, f: &mut Frame<B>, area: Rect, secret: &ManagedSecret) {
        let content_text = if secret.is_encrypted {
            "🔒 Content is encrypted. Use decrypt command to view."
        } else if self.viewer_state.show_full_content {
            "⚠️ DANGER: Full content would be shown here.\nThis is disabled for security reasons."
        } else {
            "🔍 Content preview disabled for security.\nUse 'show-content' command to view (dangerous)."
        };
        
        let content = Paragraph::new(content_text)
            .block(Block::default().borders(Borders::ALL).title("Content"))
            .style(CargoStyle::warning())
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        
        f.render_widget(content, area);
    }

    /// Render secret editor
    fn render_secret_editor<B: Backend>(&self, f: &mut Frame<B>, area: Rect, secret: &ManagedSecret) {
        let editor_text = "Edit mode is not yet implemented.\nThis will allow editing secret metadata and notes.";
        
        let editor = Paragraph::new(editor_text)
            .block(Block::default().borders(Borders::ALL).title("Editor"))
            .style(CargoStyle::info())
            .alignment(Alignment::Center);
        
        f.render_widget(editor, area);
    }

    /// Render secret actions
    fn render_secret_actions<B: Backend>(&self, f: &mut Frame<B>, area: Rect, secret: &ManagedSecret) {
        let actions_text = if secret.is_encrypted {
            "Space: Decrypt | c: Copy | e: Edit | m: Metadata | ESC: Close"
        } else {
            "Space: Encrypt | c: Copy | e: Edit | m: Metadata | ESC: Close"
        };
        
        let actions = Paragraph::new(actions_text)
            .block(Block::default().borders(Borders::ALL))
            .style(CargoStyle::muted())
            .alignment(Alignment::Center);
        
        f.render_widget(actions, area);
    }

    /// Render no selection message
    fn render_no_selection<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let message = "Select a secret from the list to view details.\n\nNavigation:\n- j/k or ↑/↓ to move\n- Enter to select\n- / to search\n- Space to toggle encryption";
        
        let placeholder = Paragraph::new(message)
            .block(Block::default().borders(Borders::ALL).title("Secret Details"))
            .style(CargoStyle::muted())
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        
        f.render_widget(placeholder, area);
    }
}

impl PartialEq for RiskLevel {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

impl PartialOrd for RiskLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_val = match self {
            RiskLevel::Low => 0,
            RiskLevel::Medium => 1,
            RiskLevel::High => 2,
            RiskLevel::Critical => 3,
        };
        let other_val = match other {
            RiskLevel::Low => 0,
            RiskLevel::Medium => 1,
            RiskLevel::High => 2,
            RiskLevel::Critical => 3,
        };
        self_val.cmp(&other_val)
    }
}

impl PartialEq for SecretType {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

impl PartialOrd for SecretType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SecretType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        format!("{:?}", self).cmp(&format!("{:?}", other))
    }
}