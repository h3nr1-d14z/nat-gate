/// Format a number with thousand separators
pub fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();

    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }

    result
}

/// Format bytes in human-readable form
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Parse iptables counter format (handles K, M, G suffixes)
pub fn parse_iptables_number(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }

    let last_char = s.chars().last().unwrap();
    let (num_str, multiplier) = match last_char {
        'K' => (&s[..s.len() - 1], 1_000u64),
        'M' => (&s[..s.len() - 1], 1_000_000u64),
        'G' => (&s[..s.len() - 1], 1_000_000_000u64),
        _ => (s, 1u64),
    };

    num_str.parse::<u64>().unwrap_or(0) * multiplier
}

/// Truncate a string to a maximum length, adding "..." if truncated.
/// Safe for Unicode strings.
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s.chars().take(max_len).collect()
    } else {
        let truncated: String = s.chars().take(max_len - 3).collect();
        format!("{truncated}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(100), "100");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1234567), "1,234,567");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
    }

    #[test]
    fn test_parse_iptables_number() {
        assert_eq!(parse_iptables_number("0"), 0);
        assert_eq!(parse_iptables_number("1234"), 1234);
        assert_eq!(parse_iptables_number("5K"), 5000);
        assert_eq!(parse_iptables_number("10M"), 10_000_000);
        assert_eq!(parse_iptables_number("2G"), 2_000_000_000);
        assert_eq!(parse_iptables_number(""), 0);
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 8), "hello...");
        assert_eq!(truncate_string("hi", 2), "hi");
        // Unicode test
        assert_eq!(truncate_string("héllo wörld", 8), "héllo...");
    }
}
