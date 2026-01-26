use serde::Serialize;
use serde_json::{json, Value};

/// Standardized JSON output wrapper
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct JsonOutput<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[allow(dead_code)]
impl<T: Serialize> JsonOutput<T> {
    /// Create a successful response with data
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(message: String) -> JsonOutput<()> {
        JsonOutput {
            success: false,
            data: None,
            error: Some(message),
        }
    }

    /// Print as pretty-printed JSON
    pub fn print(&self) {
        println!("{}", serde_json::to_string_pretty(self).unwrap_or_default());
    }
}

/// Print a simple success message in JSON format
#[allow(dead_code)]
pub fn print_success_message(message: &str) {
    let output = json!({
        "success": true,
        "message": message
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
}

/// Print an error message in JSON format
pub fn print_error(message: &str) {
    let output = json!({
        "success": false,
        "error": message
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
}

/// Print a list of items in JSON format
pub fn print_list<T: Serialize>(items: &[T], count_label: &str) {
    let output = json!({
        "success": true,
        "data": {
            count_label: items,
            "count": items.len()
        }
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
}

/// Print arbitrary JSON value
pub fn print_value(value: Value) {
    println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
}

/// Format a dry-run action as JSON
pub fn print_dry_run_action(action: &str, details: Value) {
    let output = json!({
        "dry_run": true,
        "action": action,
        "details": details
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
}

/// Print multiple dry-run actions
pub fn print_dry_run_actions(actions: Vec<Value>) {
    let output = json!({
        "dry_run": true,
        "actions": actions,
        "count": actions.len()
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_output_success() {
        let output = JsonOutput::success(vec!["item1", "item2"]);
        assert!(output.success);
        assert!(output.data.is_some());
        assert!(output.error.is_none());
    }

    #[test]
    fn test_json_output_error() {
        let output: JsonOutput<()> = JsonOutput::<()>::error("Something went wrong".to_string());
        assert!(!output.success);
        assert!(output.data.is_none());
        assert!(output.error.is_some());
    }
}
