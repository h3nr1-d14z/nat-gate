use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::*,
    Frame,
};

use super::app::{App, Screen};
use super::widgets::{
    add_rule_modal, confirm_modal, help_modal, peer_picker_modal, rules_table, sessions_table,
    stats_panel, status_bar,
};

/// Main render function
pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    // Main layout: Header, Body, Footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Body (rules + status)
            Constraint::Length(3), // Footer
        ])
        .split(area);

    // Render header
    render_header(frame, app, chunks[0]);

    // Render body — the live sessions panel takes over the full body when
    // active; otherwise show the normal rules table + status panel.
    if app.screen == Screen::Sessions {
        sessions_table::render(frame, app, chunks[1]);
    } else {
        render_body(frame, app, chunks[1]);
    }

    // Render footer (keybindings)
    status_bar::render(frame, app, chunks[2]);

    // Render modals on top if needed
    match &app.screen {
        Screen::AddRule => {
            add_rule_modal::render(frame, app);
        }
        Screen::Help => {
            help_modal::render(frame);
        }
        Screen::Confirm(action) => {
            confirm_modal::render(frame, action);
        }
        Screen::PeerPicker => {
            peer_picker_modal::render(frame, app);
        }
        Screen::Sessions | Screen::Main => {}
    }
}

/// Render the header
fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let ip_mode = if app.ipv6_mode { "IPv6" } else { "IPv4" };
    let title = format!(" nat-gate TUI  [{ip_mode}] ");

    let header = ratatui::widgets::Block::default()
        .borders(ratatui::widgets::Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(title)
        .title_style(Style::default().fg(Color::Cyan).bold());

    frame.render_widget(header, area);

    // Render message if present
    if let Some((msg, is_error)) = &app.message {
        let msg_style = if *is_error {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Green)
        };

        let msg_span = Span::styled(msg, msg_style);
        let msg_line = Line::from(vec![msg_span]);

        // Position message on the right side of the header
        let msg_area = Rect {
            x: area.x + area.width.saturating_sub(msg.len() as u16 + 3),
            y: area.y + 1,
            width: msg.len() as u16 + 2,
            height: 1,
        };

        frame.render_widget(ratatui::widgets::Paragraph::new(msg_line), msg_area);
    }
}

/// Render the body (rules table + status panel)
fn render_body(frame: &mut Frame, app: &mut App, area: Rect) {
    // Split body into rules table and status panel
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(8),    // Rules table
            Constraint::Length(5), // Status panel
        ])
        .split(area);

    // Render rules table
    rules_table::render(frame, app, chunks[0]);

    // Render status panel
    stats_panel::render(frame, app, chunks[1]);
}
