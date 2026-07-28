//! Documentation rendering utilities.

/// Renders source code with syntax highlighting (simple HTML).
pub fn code_to_html(code: &str, lang: &str) -> String {
    let escaped = code
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!("<pre><code class=\"language-{lang}\">{escaped}</code></pre>")
}

/// Render a table of contents from section headings.
pub fn render_toc(sections: &[(&str, &str, u32)]) -> String {
    let mut toc = String::from("<nav><ul>\n");
    for (id, title, level) in sections {
        let indent = "  ".repeat(*level as usize - 1);
        toc.push_str(&format!("{indent}<li><a href=\"#{id}\">{title}</a></li>\n"));
    }
    toc.push_str("</ul></nav>\n");
    toc
}

/// Convert markdown to basic HTML.
pub fn markdown_to_html(md: &str) -> String {
    let mut html = String::new();
    let mut in_code_block = false;

    for line in md.lines() {
        if line.starts_with("```") {
            in_code_block = !in_code_block;
            if in_code_block {
                html.push_str("<pre><code>");
            } else {
                html.push_str("</code></pre>\n");
            }
            continue;
        }

        if in_code_block {
            html.push_str(&format!("{}\n", line.replace('&', "&amp;").replace('<', "&lt;")));
            continue;
        }

        if line.starts_with('#') {
            let level = line.chars().take_while(|c| *c == '#').count();
            let title = line.trim_start_matches('#').trim();
            let id = title.to_lowercase().replace(' ', "-");
            html.push_str(&format!("<h{level} id=\"{id}\">{title}</h{level}>\n"));
        } else if line.is_empty() {
            html.push_str("<br>\n");
        } else {
            html.push_str(&format!("<p>{}</p>\n", line));
        }
    }

    html
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markdown_heading() {
        let html = markdown_to_html("# Hello World");
        assert!(html.contains("<h1"));
        assert!(html.contains("Hello World"));
    }

    #[test]
    fn test_code_highlighting() {
        let html = code_to_html("fn main() {}", "rust");
        assert!(html.contains("fn main()"));
        assert!(html.contains("<code"));
    }
}
