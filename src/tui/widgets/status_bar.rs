use ratatui::{
    layout::Rect,
    prelude::*,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::tui::app::App;

/// Render the status bar with keybinding hints
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let ip_mode = if app.ipv6_mode { "4" } else { "6" };

    let keybindings = vec![
        ("a", "add"),
        ("d", "delete"),
        ("f", "flush"),
        ("r", "refresh"),
        (ip_mode, if app.ipv6_mode { "IPv4" } else { "IPv6" }),
        ("?", "help"),
        ("q", "quit"),
    ];

    let mut spans = Vec::new();
    for (i, (key, desc)) in keybindings.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            format!("[{key}]"),
            Style::default().fg(Color::Yellow).bold(),
        ));
        spans.push(Span::styled(
            (*desc).to_string(),
            Style::default().fg(Color::White),
        ));
    }

    let line = Line::from(spans);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Gray));

    let paragraph = Paragraph::new(line)
        .block(block)
        .alignment(ratatui::layout::Alignment::Center);

    frame.render_widget(paragraph, area);
}
