pub mod add_rule_modal;
pub mod confirm_modal;
pub mod help_modal;
pub mod peer_picker_modal;
pub mod rules_table;
pub mod stats_panel;
pub mod status_bar;

use ratatui::layout::Rect;

/// Create a centered rectangle within the given area
pub fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;

    Rect {
        x,
        y,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}
