use ratatui::{
    layout::Rect,
    prelude::*,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::tui::app::App;
use crate::utils::{format_bytes, format_number};

/// Render the system status panel
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Gray))
        .title(" System Status ")
        .title_style(Style::default().fg(Color::Blue).bold());

    // Build status line
    let ipv4_status = if app.ipv4_forwarding {
        Span::styled("IPv4", Style::default().fg(Color::Green))
    } else {
        Span::styled("IPv4", Style::default().fg(Color::Red))
    };

    let ipv4_icon = if app.ipv4_forwarding {
        Span::styled(" \u{2713}", Style::default().fg(Color::Green))
    } else {
        Span::styled(" \u{2717}", Style::default().fg(Color::Red))
    };

    let ipv6_status = if app.ipv6_forwarding {
        Span::styled("IPv6", Style::default().fg(Color::Green))
    } else {
        Span::styled("IPv6", Style::default().fg(Color::Red))
    };

    let ipv6_icon = if app.ipv6_forwarding {
        Span::styled(" \u{2713}", Style::default().fg(Color::Green))
    } else {
        Span::styled(" \u{2717}", Style::default().fg(Color::Red))
    };

    let rules_count = app.rules.len();
    let rules_text = format!("  Rules: {rules_count} active");

    // Calculate totals
    let total_packets: u64 = app.stats.iter().map(|s| s.packets).sum();
    let total_bytes: u64 = app.stats.iter().map(|s| s.bytes).sum();
    let totals_text = format!(
        "  Traffic: {} pkts, {}",
        format_number(total_packets),
        format_bytes(total_bytes)
    );

    let status_line = Line::from(vec![
        Span::raw("  IP Forwarding: "),
        ipv4_status,
        ipv4_icon,
        Span::raw("  "),
        ipv6_status,
        ipv6_icon,
        Span::styled(rules_text, Style::default().fg(Color::Cyan)),
        Span::styled(totals_text, Style::default().fg(Color::Yellow)),
    ]);

    let paragraph = Paragraph::new(status_line).block(block);

    frame.render_widget(paragraph, area);
}
