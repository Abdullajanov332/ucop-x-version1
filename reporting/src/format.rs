//! Report formatting utilities - rendering and styling helpers.

/// Style configuration for report rendering.
#[derive(Debug, Clone)]
pub struct ReportStyle {
    pub primary_color: String,
    pub font_family: String,
    pub logo_path: Option<String>,
    pub show_page_numbers: bool,
    pub show_toc: bool,
}

impl Default for ReportStyle {
    fn default() -> Self {
        Self {
            primary_color: "#1a73e8".into(),
            font_family: "Arial, sans-serif".into(),
            logo_path: None,
            show_page_numbers: true,
            show_toc: true,
        }
    }
}

/// Wrap a string to a maximum line width.
pub fn word_wrap(text: &str, max_width: usize) -> String {
    let mut result = String::new();
    let mut line_len = 0;

    for word in text.split_whitespace() {
        if line_len + word.len() + 1 > max_width && line_len > 0 {
            result.push('\n');
            line_len = 0;
        }
        if line_len > 0 {
            result.push(' ');
            line_len += 1;
        }
        result.push_str(word);
        line_len += word.len();
    }

    result
}

/// Sanitize a string for HTML output.
pub fn sanitize_html(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_wrap() {
        let text = "This is a long line that should be wrapped";
        let wrapped = word_wrap(text, 20);
        for line in wrapped.lines() {
            assert!(line.len() <= 20);
        }
    }

    #[test]
    fn test_sanitize_html() {
        let dirty = "<script>alert('xss')</script>";
        let clean = sanitize_html(dirty);
        assert!(!clean.contains('<'));
        assert!(!clean.contains('>'));
        assert!(clean.contains("&lt;"));
    }
}
