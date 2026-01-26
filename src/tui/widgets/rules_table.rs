use ratatui::{
    layout::Rect,
    prelude::*,
    widgets::{Block, Borders, Cell, Row, Table},
    Frame,
};

use crate::tui::app::App;
use crate::utils::format_number;

/// Render the rules table
pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let ip_mode = if app.ipv6_mode { "IPv6" } else { "IPv4" };
    let title = format!(" Forwarding Rules ({ip_mode}) ");

    // Build table rows
    let rows: Vec<Row> = if app.stats.is_empty() {
        // Show rules without stats
        app.rules
            .iter()
            .map(|rule| {
                Row::new(vec![
                    Cell::from(rule.proto.to_uppercase()),
                    Cell::from(rule.port.clone()),
                    Cell::from(rule.target.clone()),
                    Cell::from("-"),
                    Cell::from("-"),
                ])
            })
            .collect()
    } else {
        // Show stats
        app.stats
            .iter()
            .map(|stat| {
                Row::new(vec![
                    Cell::from(stat.proto.to_uppercase()),
                    Cell::from(stat.port.clone()),
                    Cell::from(stat.target.clone()),
                    Cell::from(format_number(stat.packets)),
                    Cell::from(stat.bytes_formatted.clone()),
                ])
            })
            .collect()
    };

    let selected_style = Style::default()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from("Proto").style(Style::default().bold()),
        Cell::from("Port").style(Style::default().bold()),
        Cell::from("Target").style(Style::default().bold()),
        Cell::from("Packets").style(Style::default().bold()),
        Cell::from("Bytes").style(Style::default().bold()),
    ])
    .style(Style::default().fg(Color::Yellow))
    .height(1);

    let widths = [
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Min(16),
        Constraint::Length(12),
        Constraint::Length(12),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Gray))
                .title(title)
                .title_style(Style::default().fg(Color::Blue).bold()),
        )
        .row_highlight_style(selected_style)
        .highlight_symbol(">> ");

    frame.render_stateful_widget(table, area, &mut app.rules_state);

    // Show empty state message if no rules
    if app.rules.is_empty() {
        let message = "No forwarding rules. Press 'a' to add one.";
        let msg_area = Rect {
            x: area.x + 4,
            y: area.y + 3,
            width: message.len() as u16 + 2,
            height: 1,
        };
        let msg = ratatui::widgets::Paragraph::new(message)
            .style(Style::default().fg(Color::DarkGray).italic());
        frame.render_widget(msg, msg_area);
    }
}
