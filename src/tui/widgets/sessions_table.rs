use ratatui::{
    layout::Rect,
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::tui::app::App;
use crate::utils::{format_bytes, format_number, truncate_string};

/// Render the live sessions table.
///
/// Mirrors the CLI layout: Proto / Client / Target / Port / Packets / Bytes,
/// sorted by bytes descending (collect already returns sorted from
/// fetch_live). Client and target are truncated to match the CLI column
/// widths.
pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    // Title reflects the session count, or the error/empty state.
    let title = if app.sessions_error.is_some() {
        " Live Sessions ".to_string()
    } else {
        format!(" Live Sessions ({}) ", app.sessions.len())
    };

    let selected_style = Style::default()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from("Proto").style(Style::default().bold()),
        Cell::from("Client").style(Style::default().bold()),
        Cell::from("Target").style(Style::default().bold()),
        Cell::from("Port").style(Style::default().bold()),
        Cell::from("Packets").style(Style::default().bold()),
        Cell::from("Bytes").style(Style::default().bold()),
    ])
    .style(Style::default().fg(Color::Yellow))
    .height(1);

    let widths = [
        Constraint::Length(6),
        Constraint::Length(26),
        Constraint::Length(24),
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Length(12),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Gray))
        .title(title)
        .title_style(Style::default().fg(Color::Blue).bold());

    // Error state: conntrack missing or unprivileged.
    if let Some(err) = &app.sessions_error {
        let msg = Paragraph::new(err.as_str())
            .style(Style::default().fg(Color::Red))
            .block(block);
        frame.render_widget(msg, area);
        return;
    }

    // Empty state.
    if app.sessions.is_empty() {
        let message = "No active forwarded sessions.";
        let msg = Paragraph::new(message)
            .style(Style::default().fg(Color::DarkGray).italic())
            .block(block);
        frame.render_widget(msg, area);
        return;
    }

    let rows: Vec<Row> = app
        .sessions
        .iter()
        .map(|s| {
            Row::new(vec![
                Cell::from(s.proto.to_uppercase()),
                Cell::from(truncate_string(&s.client, 26)),
                Cell::from(truncate_string(&s.target, 24)),
                Cell::from(s.port.to_string()),
                Cell::from(format_number(s.packets)),
                Cell::from(format_bytes(s.bytes)),
            ])
        })
        .collect();

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(selected_style)
        .highlight_symbol(">> ");

    frame.render_stateful_widget(table, area, &mut app.sessions_state);
}
