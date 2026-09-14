use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::app::{App, ConfirmAction, FormField, Screen};

/// Handle keyboard events based on current screen
pub fn handle_key_event(app: &mut App, key: KeyEvent) {
    // Clear old messages
    app.clear_old_message();

    match &app.screen {
        Screen::Main => handle_main_screen(app, key),
        Screen::AddRule => handle_add_rule_screen(app, key),
        Screen::Help => handle_help_screen(app, key),
        Screen::Confirm(_) => handle_confirm_screen(app, key),
        Screen::PeerPicker => handle_peer_picker_screen(app, key),
    }
}

/// Handle keys on the main screen
fn handle_main_screen(app: &mut App, key: KeyEvent) {
    match key.code {
        // Quit
        KeyCode::Char('q') | KeyCode::Esc => {
            app.running = false;
        }

        // Help
        KeyCode::Char('?') | KeyCode::Char('h') => {
            app.screen = Screen::Help;
        }

        // Navigation
        KeyCode::Up | KeyCode::Char('k') => {
            app.select_previous();
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.select_next();
        }

        // Add rule
        KeyCode::Char('a') => {
            app.add_form.reset();
            app.load_tailscale_peers();
            app.screen = Screen::AddRule;
        }

        // Delete rule
        KeyCode::Char('d') | KeyCode::Delete => {
            if let Some(idx) = app.selected_rule() {
                if !app.rules.is_empty() {
                    app.screen = Screen::Confirm(ConfirmAction::DeleteRule(idx));
                }
            }
        }

        // Flush all rules
        KeyCode::Char('f') => {
            if !app.rules.is_empty() {
                app.screen = Screen::Confirm(ConfirmAction::FlushAll);
            }
        }

        // Refresh
        KeyCode::Char('r') => {
            app.refresh_rules();
            app.refresh_stats();
            app.refresh_system_status();
            app.set_message("Refreshed".to_string(), false);
        }

        // Toggle IPv6
        KeyCode::Char('6') => {
            app.toggle_ipv6();
            let mode = if app.ipv6_mode { "IPv6" } else { "IPv4" };
            app.set_message(format!("Switched to {mode}"), false);
        }

        // Ctrl+C to quit
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.running = false;
        }

        _ => {}
    }
}

/// Handle keys on the add rule screen
fn handle_add_rule_screen(app: &mut App, key: KeyEvent) {
    match key.code {
        // Cancel
        KeyCode::Esc => {
            app.screen = Screen::Main;
        }

        // Navigate fields
        KeyCode::Tab => {
            app.add_form.focus = app.add_form.focus.next();
        }
        KeyCode::BackTab => {
            app.add_form.focus = app.add_form.focus.prev();
        }
        KeyCode::Up => {
            app.add_form.focus = app.add_form.focus.prev();
        }
        KeyCode::Down => {
            app.add_form.focus = app.add_form.focus.next();
        }

        // Handle Enter key
        KeyCode::Enter => {
            match app.add_form.focus {
                FormField::Protocol => {
                    app.add_form.protocol.toggle();
                }
                FormField::Target => {
                    // Open peer picker
                    app.load_tailscale_peers();
                    if !app.tailscale_peers.is_empty() {
                        app.screen = Screen::PeerPicker;
                    }
                }
                FormField::Cancel => {
                    app.screen = Screen::Main;
                }
                FormField::Submit => {
                    // Validate and submit
                    match app.add_form.validate() {
                        Ok(()) => match app.add_rule() {
                            Ok(()) => {
                                app.refresh_rules();
                                app.refresh_stats();
                                app.set_message("Rule added successfully".to_string(), false);
                                app.screen = Screen::Main;
                            }
                            Err(e) => {
                                app.add_form.error = Some(e);
                            }
                        },
                        Err(e) => {
                            app.add_form.error = Some(e);
                        }
                    }
                }
                _ => {}
            }
        }

        // Toggle protocol with space
        KeyCode::Char(' ') if app.add_form.focus == FormField::Protocol => {
            app.add_form.protocol.toggle();
        }

        // Text input for fields
        KeyCode::Char(c) => {
            match app.add_form.focus {
                FormField::Port => {
                    if c.is_ascii_digit() || c == '-' {
                        app.add_form.port.push(c);
                    }
                }
                FormField::Target => {
                    if c.is_ascii_digit() || c == '.' || c == ':' || c.is_ascii_hexdigit() {
                        app.add_form.target.push(c);
                    }
                }
                FormField::Interface => {
                    if c.is_ascii_alphanumeric() {
                        app.add_form.interface.push(c);
                    }
                }
                FormField::Limit if c.is_ascii_alphanumeric() || c == '/' => {
                    app.add_form.limit.push(c);
                }
                _ => {}
            }
            // Clear error when typing
            app.add_form.error = None;
        }

        // Backspace for text fields
        KeyCode::Backspace => {
            match app.add_form.focus {
                FormField::Port => {
                    app.add_form.port.pop();
                }
                FormField::Target => {
                    app.add_form.target.pop();
                }
                FormField::Interface => {
                    app.add_form.interface.pop();
                }
                FormField::Limit => {
                    app.add_form.limit.pop();
                }
                _ => {}
            }
            app.add_form.error = None;
        }

        _ => {}
    }
}

/// Handle keys on the help screen
fn handle_help_screen(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc
        | KeyCode::Char('?')
        | KeyCode::Char('h')
        | KeyCode::Char('q')
        | KeyCode::Enter => {
            app.screen = Screen::Main;
        }
        _ => {}
    }
}

/// Handle keys on the confirm screen
fn handle_confirm_screen(app: &mut App, key: KeyEvent) {
    match key.code {
        // Cancel
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            app.screen = Screen::Main;
        }

        // Confirm
        KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
            let action = match &app.screen {
                Screen::Confirm(action) => action.clone(),
                _ => return,
            };

            match action {
                ConfirmAction::DeleteRule(idx) => match app.delete_rule(idx) {
                    Ok(()) => {
                        app.refresh_rules();
                        app.refresh_stats();
                        app.set_message("Rule deleted".to_string(), false);
                    }
                    Err(e) => {
                        app.set_message(format!("Delete failed: {e}"), true);
                    }
                },
                ConfirmAction::FlushAll => match app.flush_all() {
                    Ok(()) => {
                        app.refresh_rules();
                        app.refresh_stats();
                        app.set_message("All rules flushed".to_string(), false);
                    }
                    Err(e) => {
                        app.set_message(format!("Flush failed: {e}"), true);
                    }
                },
            }

            app.screen = Screen::Main;
        }

        _ => {}
    }
}

/// Handle keys on the peer picker screen
fn handle_peer_picker_screen(app: &mut App, key: KeyEvent) {
    match key.code {
        // Cancel
        KeyCode::Esc => {
            app.screen = Screen::AddRule;
        }

        // Navigation
        KeyCode::Up | KeyCode::Char('k') => {
            app.select_previous_peer();
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.select_next_peer();
        }

        // Select
        KeyCode::Enter => {
            app.select_peer();
            app.screen = Screen::AddRule;
        }

        _ => {}
    }
}
