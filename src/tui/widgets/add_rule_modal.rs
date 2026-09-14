use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use super::centered_rect;
use crate::tui::app::{App, FormField, Protocol};

/// Render the add rule modal
pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Calculate modal size (centered, 50x20)
    let modal_width = 54;
    let modal_height = 18;
    let modal_area = centered_rect(modal_width, modal_height, area);

    // Clear the area behind the modal
    frame.render_widget(Clear, modal_area);

    // Modal border
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Add Forwarding Rule ")
        .title_style(Style::default().fg(Color::Cyan).bold());

    frame.render_widget(block, modal_area);

    // Inner area for form fields
    let inner_area = Rect {
        x: modal_area.x + 2,
        y: modal_area.y + 2,
        width: modal_area.width.saturating_sub(4),
        height: modal_area.height.saturating_sub(4),
    };

    // Layout for form fields
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Protocol
            Constraint::Length(2), // Port
            Constraint::Length(2), // Target
            Constraint::Length(2), // Interface
            Constraint::Length(2), // Limit
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // Error message
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // Buttons
        ])
        .split(inner_area);

    let form = &app.add_form;

    // Protocol field
    render_protocol_field(
        frame,
        form.protocol,
        form.focus == FormField::Protocol,
        chunks[0],
    );

    // Port field
    render_text_field(
        frame,
        "Port:",
        &form.port,
        "e.g., 443 or 8000-8080",
        form.focus == FormField::Port,
        chunks[1],
    );

    // Target field with peer picker hint
    render_target_field(
        frame,
        &form.target,
        form.focus == FormField::Target,
        chunks[2],
    );

    // Interface field
    render_text_field(
        frame,
        "Interface:",
        &form.interface,
        "(optional, e.g., eth0)",
        form.focus == FormField::Interface,
        chunks[3],
    );

    // Limit field
    render_text_field(
        frame,
        "Limit:",
        &form.limit,
        "(optional, e.g., 100/min)",
        form.focus == FormField::Limit,
        chunks[4],
    );

    // Error message
    if let Some(error) = &form.error {
        let error_text = Paragraph::new(error.as_str()).style(Style::default().fg(Color::Red));
        frame.render_widget(error_text, chunks[6]);
    }

    // Buttons
    render_buttons(
        frame,
        form.focus == FormField::Cancel,
        form.focus == FormField::Submit,
        chunks[8],
    );
}

/// Render the protocol toggle field
fn render_protocol_field(frame: &mut Frame, protocol: Protocol, focused: bool, area: Rect) {
    let label_style = if focused {
        Style::default().fg(Color::Yellow).bold()
    } else {
        Style::default().fg(Color::White)
    };

    let tcp_style = if protocol == Protocol::Tcp {
        Style::default().fg(Color::Green).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let udp_style = if protocol == Protocol::Udp {
        Style::default().fg(Color::Green).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let line = Line::from(vec![
        Span::styled("Protocol: ", label_style),
        Span::styled("[", Style::default().fg(Color::Gray)),
        Span::styled("TCP", tcp_style),
        Span::styled("] ", Style::default().fg(Color::Gray)),
        Span::styled("[", Style::default().fg(Color::Gray)),
        Span::styled("UDP", udp_style),
        Span::styled("]", Style::default().fg(Color::Gray)),
        if focused {
            Span::styled(
                "  <Space> to toggle",
                Style::default().fg(Color::DarkGray).italic(),
            )
        } else {
            Span::raw("")
        },
    ]);

    frame.render_widget(Paragraph::new(line), area);
}

/// Render a text input field
fn render_text_field(
    frame: &mut Frame,
    label: &str,
    value: &str,
    placeholder: &str,
    focused: bool,
    area: Rect,
) {
    let label_style = if focused {
        Style::default().fg(Color::Yellow).bold()
    } else {
        Style::default().fg(Color::White)
    };

    let value_style = if focused {
        Style::default().fg(Color::White).bg(Color::DarkGray)
    } else {
        Style::default().fg(Color::White)
    };

    let display_value = if value.is_empty() {
        Span::styled(placeholder, Style::default().fg(Color::DarkGray).italic())
    } else {
        Span::styled(value, value_style)
    };

    // Add cursor if focused
    let cursor = if focused {
        Span::styled("_", Style::default().fg(Color::Yellow))
    } else {
        Span::raw("")
    };

    let line = Line::from(vec![
        Span::styled(format!("{label:<12}"), label_style),
        display_value,
        cursor,
    ]);

    frame.render_widget(Paragraph::new(line), area);
}

/// Render the target field with peer picker hint
fn render_target_field(frame: &mut Frame, value: &str, focused: bool, area: Rect) {
    let label_style = if focused {
        Style::default().fg(Color::Yellow).bold()
    } else {
        Style::default().fg(Color::White)
    };

    let value_style = if focused {
        Style::default().fg(Color::White).bg(Color::DarkGray)
    } else {
        Style::default().fg(Color::White)
    };

    let display_value = if value.is_empty() {
        Span::styled("IP address", Style::default().fg(Color::DarkGray).italic())
    } else {
        Span::styled(value, value_style)
    };

    let cursor = if focused {
        Span::styled("_", Style::default().fg(Color::Yellow))
    } else {
        Span::raw("")
    };

    let picker_hint = if focused {
        Span::styled("  [Enter] Pick peer", Style::default().fg(Color::Cyan))
    } else {
        Span::raw("")
    };

    let line = Line::from(vec![
        Span::styled("Target:     ", label_style),
        display_value,
        cursor,
        picker_hint,
    ]);

    frame.render_widget(Paragraph::new(line), area);
}

/// Render the cancel/submit buttons
fn render_buttons(frame: &mut Frame, cancel_focused: bool, submit_focused: bool, area: Rect) {
    let cancel_style = if cancel_focused {
        Style::default().fg(Color::Black).bg(Color::White).bold()
    } else {
        Style::default().fg(Color::White)
    };

    let submit_style = if submit_focused {
        Style::default().fg(Color::Black).bg(Color::Green).bold()
    } else {
        Style::default().fg(Color::Green)
    };

    // Center the buttons
    let buttons_width = 26; // " [ Cancel ]  [ Add Rule ] "
    let padding = (area.width.saturating_sub(buttons_width)) / 2;

    let line = Line::from(vec![
        Span::raw(" ".repeat(padding as usize)),
        Span::styled(" Cancel ", cancel_style),
        Span::raw("  "),
        Span::styled(" Add Rule ", submit_style),
    ]);

    frame.render_widget(Paragraph::new(line), area);
}
