use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use super::centered_rect;
use crate::tui::app::ConfirmAction;

/// Render the confirmation modal
pub fn render(frame: &mut Frame, action: &ConfirmAction) {
    let area = frame.area();

    // Calculate modal size (centered)
    let modal_width = 45;
    let modal_height = 8;
    let modal_area = centered_rect(modal_width, modal_height, area);

    // Clear the area behind the modal
    frame.render_widget(Clear, modal_area);

    // Modal border
    let title = match action {
        ConfirmAction::DeleteRule(_) => " Confirm Delete ",
        ConfirmAction::FlushAll => " Confirm Flush ",
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .title(title)
        .title_style(Style::default().fg(Color::Red).bold());

    frame.render_widget(block, modal_area);

    // Inner area for message
    let inner_area = Rect {
        x: modal_area.x + 2,
        y: modal_area.y + 2,
        width: modal_area.width.saturating_sub(4),
        height: modal_area.height.saturating_sub(4),
    };

    let message = match action {
        ConfirmAction::DeleteRule(_) => "Delete this forwarding rule?",
        ConfirmAction::FlushAll => "Remove ALL forwarding rules?",
    };

    let text = vec![
        Line::from(Span::styled(message, Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Press "),
            Span::styled("[Y]", Style::default().fg(Color::Green).bold()),
            Span::raw(" to confirm, "),
            Span::styled("[N]", Style::default().fg(Color::Red).bold()),
            Span::raw(" to cancel"),
        ]),
    ];

    let paragraph = Paragraph::new(text).alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(paragraph, inner_area);
}
