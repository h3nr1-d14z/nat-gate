use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use super::centered_rect;

/// Render the help modal
pub fn render(frame: &mut Frame) {
    let area = frame.area();

    // Calculate modal size (centered)
    let modal_width = 50;
    let modal_height = 21;

    let modal_area = centered_rect(modal_width, modal_height, area);
    // Clear the area behind the modal
    frame.render_widget(Clear, modal_area);

    // Modal border
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(" Help ")
        .title_style(Style::default().fg(Color::Yellow).bold());

    frame.render_widget(block, modal_area);

    // Inner area for help text
    let inner_area = Rect {
        x: modal_area.x + 2,
        y: modal_area.y + 2,
        width: modal_area.width.saturating_sub(4),
        height: modal_area.height.saturating_sub(4),
    };

    let help_text = vec![
        Line::from(vec![Span::styled(
            "Navigation",
            Style::default().fg(Color::Cyan).bold(),
        )]),
        Line::from(vec![
            Span::styled("  \u{2191}/k", Style::default().fg(Color::Yellow)),
            Span::raw("        Move up"),
        ]),
        Line::from(vec![
            Span::styled("  \u{2193}/j", Style::default().fg(Color::Yellow)),
            Span::raw("        Move down"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Actions",
            Style::default().fg(Color::Cyan).bold(),
        )]),
        Line::from(vec![
            Span::styled("  a", Style::default().fg(Color::Yellow)),
            Span::raw("          Add new rule"),
        ]),
        Line::from(vec![
            Span::styled("  d/Del", Style::default().fg(Color::Yellow)),
            Span::raw("      Delete selected rule"),
        ]),
        Line::from(vec![
            Span::styled("  f", Style::default().fg(Color::Yellow)),
            Span::raw("          Flush all rules"),
        ]),
        Line::from(vec![
            Span::styled("  r", Style::default().fg(Color::Yellow)),
            Span::raw("          Refresh data"),
        ]),
        Line::from(vec![
            Span::styled("  6", Style::default().fg(Color::Yellow)),
            Span::raw("          Toggle IPv4/IPv6 mode"),
        ]),
        Line::from(vec![
            Span::styled("  s", Style::default().fg(Color::Yellow)),
            Span::raw("          Live sessions panel"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "General",
            Style::default().fg(Color::Cyan).bold(),
        )]),
        Line::from(vec![
            Span::styled("  ?/h", Style::default().fg(Color::Yellow)),
            Span::raw("        Toggle this help"),
        ]),
        Line::from(vec![
            Span::styled("  q/Esc", Style::default().fg(Color::Yellow)),
            Span::raw("      Quit / Close modal"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Press any key to close",
            Style::default().fg(Color::DarkGray).italic(),
        )]),
    ];

    let paragraph = Paragraph::new(help_text);
    frame.render_widget(paragraph, inner_area);
}
