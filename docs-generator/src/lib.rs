//! UCOP-X Documentation Generator
//!
//! Generates documentation from source code comments, module metadata,
//! and architecture definitions. Supports Markdown and HTML output.

#![forbid(unsafe_code)]

pub mod parser;
pub mod render;

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// A documented module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentedModule {
    pub name: String,
    pub path: String,
    pub description: String,
    pub items: Vec<DocumentedItem>,
    pub submodules: Vec<String>,
}

/// A documented code item (function, struct, trait, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentedItem {
    pub name: String,
    pub item_type: String,
    pub signature: String,
    pub description: String,
    pub parameters: Vec<DocParameter>,
    pub return_type: Option<String>,
    pub examples: Vec<String>,
    pub visibility: String,
}

/// A function/method parameter documentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocParameter {
    pub name: String,
    pub param_type: String,
    pub description: String,
    pub optional: bool,
}

/// Documentation set for the entire project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocSet {
    pub project_name: String,
    pub version: String,
    pub modules: Vec<DocumentedModule>,
    pub generated: String,
}

impl DocSet {
    pub fn new(project_name: &str, version: &str) -> Self {
        Self {
            project_name: project_name.to_string(),
            version: version.to_string(),
            modules: Vec::new(),
            generated: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Add a module to the documentation set.
    pub fn add_module(&mut self, module: DocumentedModule) {
        self.modules.push(module);
    }

    /// Render the documentation set to a string.
    pub fn render(&self, format: &str) -> String {
        match format {
            "json" => serde_json::to_string_pretty(self).unwrap_or_default(),
            "html" => self.render_html(),
            _ => self.render_markdown(),
        }
    }

    fn render_markdown(&self) -> String {
        let mut md = format!("# {} v{}\n\n", self.project_name, self.version);
        md.push_str("## Modules\n\n");

        for module in &self.modules {
            md.push_str(&format!("### `{}`\n\n", module.name));
            md.push_str(&format!("{}\n\n", module.description));

            if !module.items.is_empty() {
                md.push_str("#### Items\n\n");
                for item in &module.items {
                    md.push_str(&format!("- **`{}`** ({}) - {}\n", item.name, item.item_type, item.description));
                }
                md.push_str("\n");
            }
        }

        md
    }

    fn render_html(&self) -> String {
        let mut html = format!(
            "<!DOCTYPE html><html><head><title>{}</title>\
             <style>body{{font-family:sans-serif;margin:2em}} \
             h1{{color:#1a73e8}}</style></head><body>",
            self.project_name
        );
        html.push_str(&format!("<h1>{} v{}</h1>", self.project_name, self.version));

        for module in &self.modules {
            html.push_str(&format!("<h2><code>{}</code></h2>", module.name));
            html.push_str(&format!("<p>{}</p>", module.description));
            for item in &module.items {
                html.push_str(&format!(
                    "<div style='margin:8px 0;padding:8px;border:1px solid #ddd'>\
                     <strong>{}</strong> <em>({})</em><p>{}</p></div>",
                    item.name, item.item_type, item.description
                ));
            }
        }

        html.push_str("</body></html>");
        html
    }
}

/// Documentation generator.
#[derive(Debug, Default)]
pub struct DocsGenerator;

impl DocsGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate documentation for all Rust source files in a directory.
    pub fn generate_from_dir(&self, _dir: &std::path::Path) -> DocSet {
        let mut docset = DocSet::new("UCOP-X Enterprise", "0.1.0");

        // Walk source directory and extract doc comments
        if _dir.exists() {
            for entry in walkdir::WalkDir::new(_dir) {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.extension().map_or(false, |e| e == "rs") {
                        if let Ok(content) = std::fs::read_to_string(path) {
                            let module = parser::parse_module(path, &content);
                            docset.add_module(module);
                        }
                    }
                }
            }
        }

        docset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docset_creation() {
        let docset = DocSet::new("Test", "1.0");
        assert_eq!(docset.project_name, "Test");
        assert_eq!(docset.version, "1.0");
    }

    #[test]
    fn test_render_json() {
        let docset = DocSet::new("Test", "1.0");
        let json = docset.render("json");
        assert!(json.contains("Test"));
    }
}
