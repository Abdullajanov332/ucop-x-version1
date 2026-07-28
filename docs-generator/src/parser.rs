//! Source code documentation parser.

use crate::{DocumentedItem, DocumentedModule, DocParameter};

/// Parse a Rust source file and extract documentation.
pub fn parse_module(path: &std::path::Path, content: &str) -> DocumentedModule {
    let module_name = path
        .file_stem()
        .map(|s| s.to_string_lossy().into())
        .unwrap_or_else(|| "unknown".into());

    let path_str = path.to_string_lossy().to_string();
    let mut items = Vec::new();

    // Simple extraction: look for doc comments followed by function/struct/trait/enum
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // Check for doc comment (/// or //!)
        if trimmed.starts_with("///") {
            let doc_comment = trimmed.trim_start_matches("///").trim();
            let mut doc_lines = vec![doc_comment];

            // Collect consecutive doc comments
            while i + 1 < lines.len() && lines[i + 1].trim().starts_with("///") {
                i += 1;
                doc_lines.push(lines[i].trim().trim_start_matches("///").trim());
            }

            // Check what follows
            if i + 1 < lines.len() {
                let next = lines[i + 1].trim();

                if next.starts_with("pub fn") || next.starts_with("fn") {
                    let sig = next.split('{').next().unwrap_or(next).trim().to_string();
                    let name = sig
                        .split_whitespace()
                        .filter(|s| !s.starts_with("pub") && !s.starts_with("fn"))
                        .next()
                        .unwrap_or("unknown")
                        .trim_end_matches('(')
                        .to_string();

                    items.push(DocumentedItem {
                        name,
                        item_type: "function".into(),
                        signature: sig,
                        description: doc_lines.join(" "),
                        parameters: Vec::new(),
                        return_type: None,
                        examples: Vec::new(),
                        visibility: if next.starts_with("pub") { "public" } else { "private" }.into(),
                    });
                } else if next.starts_with("pub struct") || next.starts_with("struct") {
                    let name = next
                        .split_whitespace()
                        .filter(|s| !s.starts_with("pub") && !s.starts_with("struct"))
                        .next()
                        .unwrap_or("unknown")
                        .to_string();

                    items.push(DocumentedItem {
                        name,
                        item_type: "struct".into(),
                        signature: next.to_string(),
                        description: doc_lines.join(" "),
                        parameters: Vec::new(),
                        return_type: None,
                        examples: Vec::new(),
                        visibility: if next.starts_with("pub") { "public" } else { "private" }.into(),
                    });
                } else if next.starts_with("pub enum") || next.starts_with("enum") {
                    let name = next
                        .split_whitespace()
                        .filter(|s| !s.starts_with("pub") && !s.starts_with("enum"))
                        .next()
                        .unwrap_or("unknown")
                        .to_string();

                    items.push(DocumentedItem {
                        name,
                        item_type: "enum".into(),
                        signature: next.to_string(),
                        description: doc_lines.join(" "),
                        parameters: Vec::new(),
                        return_type: None,
                        examples: Vec::new(),
                        visibility: if next.starts_with("pub") { "public" } else { "private" }.into(),
                    });
                } else if next.starts_with("pub trait") || next.starts_with("trait") {
                    let name = next
                        .split_whitespace()
                        .filter(|s| !s.starts_with("pub") && !s.starts_with("trait"))
                        .next()
                        .unwrap_or("unknown")
                        .to_string();

                    items.push(DocumentedItem {
                        name,
                        item_type: "trait".into(),
                        signature: next.to_string(),
                        description: doc_lines.join(" "),
                        parameters: Vec::new(),
                        return_type: None,
                        examples: Vec::new(),
                        visibility: if next.starts_with("pub") { "public" } else { "private" }.into(),
                    });
                }
            }
        }

        i += 1;
    }

    DocumentedModule {
        name: module_name,
        path: path_str,
        description: String::new(),
        items,
        submodules: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_function() {
        let content = r#"
/// This is a test function.
pub fn hello() {
    println!("hello");
}
"#;
        let module = parse_module(std::path::Path::new("test.rs"), content);
        assert_eq!(module.items.len(), 1);
        assert_eq!(module.items[0].name, "hello");
        assert_eq!(module.items[0].item_type, "function");
    }
}
