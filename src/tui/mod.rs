mod app;
mod handlers;
mod ui;
mod widgets;

use app::{App, Screen};

use std::io;
use std::time::Duration;

use crossterm::{
    cursor::Show,
    event::{self, DisableMouseCapture, EnableMouseCapture, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;

use crate::backend;
use crate::utils::check_root;

/// Constants for TUI timing
const POLL_INTERVAL_MS: u64 = 250;
const STATS_REFRESH_SECS: u64 = 5;
const MESSAGE_TIMEOUT_SECS: u64 = 3;
const SESSIONS_REFRESH_SECS: u64 = 5;

/// Guard to ensure terminal is restored on drop (including panics)
struct TerminalGuard {
    active: bool,
}

impl TerminalGuard {
    fn new() -> Self {
        Self { active: true }
    }

    /// Mark the guard as cleanly deactivated (normal exit path)
    fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.active {
            // Restore terminal state - ignore errors during cleanup
            let _ = disable_raw_mode();
            let _ = execute!(
                io::stdout(),
                LeaveAlternateScreen,
                DisableMouseCapture,
                Show
            );
        }
    }
}

/// Run the TUI application
pub fn run() -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    backend::check_dependencies()?;

    // Setup terminal
    enable_raw_mode().map_err(|e| format!("Failed to enable raw mode: {e}"))?;

    // Create guard AFTER enabling raw mode - it will restore on drop
    let mut guard = TerminalGuard::new();

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .map_err(|e| format!("Failed to enter alternate screen: {e}"))?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal =
        Terminal::new(backend).map_err(|e| format!("Failed to create terminal: {e}"))?;

    // Create app state
    let mut app = App::default();

    // Initial data load
    app.refresh_rules();
    app.refresh_stats();
    app.refresh_system_status();

    // Run main loop
    let result = run_app(&mut terminal, &mut app);

    // Clean restoration path
    disable_raw_mode().map_err(|e| format!("Failed to disable raw mode: {e}"))?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .map_err(|e| format!("Failed to leave alternate screen: {e}"))?;
    terminal
        .show_cursor()
        .map_err(|e| format!("Failed to show cursor: {e}"))?;

    // Deactivate guard since we cleaned up successfully
    guard.deactivate();

    result
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<(), String> {
    loop {
        // Draw UI
        terminal
            .draw(|frame| ui::render(frame, app))
            .map_err(|e| format!("Failed to draw: {e}"))?;

        // Handle events with timeout for auto-refresh
        if event::poll(Duration::from_millis(POLL_INTERVAL_MS))
            .map_err(|e| format!("Event poll error: {e}"))?
        {
            if let Event::Key(key) = event::read().map_err(|e| format!("Event read error: {e}"))? {
                handlers::handle_key_event(app, key);
            }
        }

        // Auto-refresh stats
        if app.should_refresh_stats() {
            app.refresh_stats();
        }

        // Auto-refresh the live sessions panel while it's visible
        if app.screen == Screen::Sessions && app.should_refresh_sessions() {
            app.refresh_sessions();
        }

        // Check if we should exit
        if !app.running {
            return Ok(());
        }
    }
}

/// Get the stats refresh interval in seconds
pub(crate) const fn stats_refresh_secs() -> u64 {
    STATS_REFRESH_SECS
}

/// Get the message timeout in seconds
pub(crate) const fn message_timeout_secs() -> u64 {
    MESSAGE_TIMEOUT_SECS
}

/// Get the sessions refresh interval in seconds
pub(crate) const fn sessions_refresh_secs() -> u64 {
    SESSIONS_REFRESH_SECS
}
