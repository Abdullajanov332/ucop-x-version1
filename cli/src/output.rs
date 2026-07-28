//! Output formatting for CLI commands.
//! Provides structured output rendering (JSON, YAML, table, plain text).

use comfy_table::{Cell, CellAlignment, ContentArrangement, Table};
use serde::Serialize;
use std::fmt;

/// Output format for CLI commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Plain human-readable text.
    Plain,
    /// JSON output.
    Json,
    /// YAML output.
    Yaml,
    /// Formatted table.
    Table,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "plain" | "text" => Ok(Self::Plain),
            "json" => Ok(Self::Json),
            "yaml" => Ok(Self::Yaml),
            "table" => Ok(Self::Table),
            _ => Err(format!("unknown output format: {s} (expected plain, json, yaml, table)")),
        }
    }
}

/// Render structured output to stdout.
pub fn render<T: Serialize + fmt::Debug>(data: &T, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(data).unwrap_or_default(),
        OutputFormat::Yaml => serde_yaml::to_string(data).unwrap_or_default(),
        OutputFormat::Table | OutputFormat::Plain => format!("{data:#?}"),
    }
}

/// Build a formatted table from headers and rows.
pub fn build_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .load_preset(comfy_table::presets::UTF8_FULL);

    let header_cells: Vec<Cell> = headers
        .iter()
        .map(|h| Cell::new(*h).set_alignment(CellAlignment::Center).add_attribute(comfy_table::Attribute::Bold))
        .collect();
    table.set_header(header_cells);

    for row in rows {
        table.add_row(row);
    }

    table.to_string()
}

/// Print a success message.
pub fn print_success(msg: impl fmt::Display) {
    println!("{} {}", colored::Colorize::green("✔"), msg);
}

/// Print an error message.
pub fn print_error(msg: impl fmt::Display) {
    eprintln!("{} {}", colored::Colorize::red("✘"), msg);
}

/// Print a warning message.
pub fn print_warning(msg: impl fmt::Display) {
    println!("{} {}", colored::Colorize::yellow("⚠"), msg);
}

/// Print an info message.
pub fn print_info(msg: impl fmt::Display) {
    println!("{} {}", colored::Colorize::cyan("ℹ"), msg);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_output_format_parsing() {
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!("table".parse::<OutputFormat>().unwrap(), OutputFormat::Table);
        assert_eq!("plain".parse::<OutputFormat>().unwrap(), OutputFormat::Plain);
        assert!("invalid".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_json_render() {
        let data = json!({"name": "test", "value": 42});
        let rendered = render(&data, OutputFormat::Json);
        assert!(rendered.contains("test"));
        assert!(rendered.contains("42"));
    }

    #[test]
    fn test_table_building() {
        let table = build_table(
            &["Name", "Status"],
            &[vec!["module-a".into(), "running".into()]],
        );
        assert!(table.contains("module-a"));
        assert!(table.contains("running"));
    }
}
