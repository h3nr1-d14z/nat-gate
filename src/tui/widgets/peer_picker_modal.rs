use ratatui::{
    layout::Rect,
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use super::centered_rect;
use crate::tui::app::App;
use crate::utils::truncate_string;

/// Maximum visible peers in the modal
const VISIBLE_PEERS: usize = 10;

/// Render the Tailscale peer picker modal
pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Calculate modal size based on number of peers (with max height)
    let modal_width = 55;
    let peer_count = app.tailscale_peers.len().min(VISIBLE_PEERS);
    let modal_height = (peer_count + 6).min(20) as u16;
    let modal_area = centered_rect(modal_width, modal_height, area);

    // Clear the area behind the modal
    frame.render_widget(Clear, modal_area);

    // Modal border
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Select Tailscale Peer ")
        .title_style(Style::default().fg(Color::Cyan).bold());

    frame.render_widget(block, modal_area);

    // Inner area for peer list
    let inner_area = Rect {
        x: modal_area.x + 2,
        y: modal_area.y + 2,
        width: modal_area.width.saturating_sub(4),
        height: modal_area.height.saturating_sub(5),
    };

    if app.tailscale_peers.is_empty() {
        let empty_text = Paragraph::new("No Tailscale peers found.")
            .style(Style::default().fg(Color::DarkGray).italic());
        frame.render_widget(empty_text, inner_area);
    } else {
        // Build peer list with scrolling
        let mut lines: Vec<Line> = Vec::new();

        // Show scroll indicator if there are more peers above
        if app.has_peers_above() {
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled("\u{25B2} more above", Style::default().fg(Color::DarkGray).italic()),
            ]));
        }

        for (i, peer) in app.visible_peers() {
            let is_selected = i == app.peer_selection;

            let prefix = if is_selected {
                Span::styled("> ", Style::default().fg(Color::Yellow).bold())
            } else {
                Span::raw("  ")
            };

            let name_style = if is_selected {
                Style::default().fg(Color::White).bold()
            } else {
                Style::default().fg(Color::White)
            };

            let ip = peer
                .ipv4
                .as_ref()
                .or(peer.ipv6.as_ref())
                .map(|s| s.as_str())
                .unwrap_or("-");

            let status = if peer.online {
                Span::styled("online", Style::default().fg(Color::Green))
            } else {
                Span::styled("offline", Style::default().fg(Color::Red))
            };

            // Use Unicode-safe truncation
            let name = truncate_string(&peer.hostname, 18);

            lines.push(Line::from(vec![
                prefix,
                Span::styled(format!("{name:<18}"), name_style),
                Span::styled(format!("{ip:<16}"), Style::default().fg(Color::Cyan)),
                status,
            ]));
        }

        // Show scroll indicator if there are more peers below
        if app.has_peers_below() {
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled("\u{25BC} more below", Style::default().fg(Color::DarkGray).italic()),
            ]));
        }

        let paragraph = Paragraph::new(lines);
        frame.render_widget(paragraph, inner_area);
    }

    // Footer with keybindings
    let footer_area = Rect {
        x: modal_area.x + 2,
        y: modal_area.y + modal_area.height - 2,
        width: modal_area.width.saturating_sub(4),
        height: 1,
    };

    let footer = Line::from(vec![
        Span::styled("[Enter]", Style::default().fg(Color::Yellow)),
        Span::raw(" Select  "),
        Span::styled("[Esc]", Style::default().fg(Color::Yellow)),
        Span::raw(" Cancel"),
    ]);

    frame.render_widget(Paragraph::new(footer), footer_area);
}
