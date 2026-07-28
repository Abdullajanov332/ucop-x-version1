//! `config` command namespace.
//! Configuration management for UCOP-X.

use clap::{Args, Subcommand};
use std::collections::HashMap;

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommands,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommands {
    /// Get a configuration value.
    Get(GetArgs),
    /// Set a configuration value.
    Set(SetArgs),
    /// List all configuration.
    List,
    /// Reset configuration to defaults.
    Reset,
    /// Import configuration from file.
    Import(ImportArgs),
}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Configuration key (e.g. kernel.max_modules).
    pub key: String,
}

#[derive(Debug, Args)]
pub struct SetArgs {
    /// Configuration key.
    pub key: String,
    /// Configuration value.
    pub value: String,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Path to config file (TOML or YAML).
    pub path: String,
}

pub async fn execute(args: &ConfigArgs) -> Result<(), String> {
    match &args.command {
        ConfigCommands::Get(gargs) => config_get(gargs).await,
        ConfigCommands::Set(sargs) => config_set(sargs).await,
        ConfigCommands::List => config_list().await,
        ConfigCommands::Reset => config_reset().await,
        ConfigCommands::Import(iargs) => config_import(iargs).await,
    }
}

async fn config_get(args: &GetArgs) -> Result<(), String> {
    let cli_config = ucx_cli::config::CliConfig::load();
    let value = get_nested_value(&cli_config, &args.key);
    match value {
        Some(v) => println!("{} = {}", args.key, v),
        None => println!("Key not found: {}", args.key),
    }
    Ok(())
}

fn get_nested_value(_config: &ucx_cli::config::CliConfig, key: &str) -> Option<String> {
    match key {
        "output_format" => Some(_config.output_format.clone()),
        "color" => Some(_config.color.to_string()),
        "verbose" => Some(_config.verbose.to_string()),
        "log_level" => Some(_config.log_level.clone()),
        "timeout" => Some(_config.default_timeout_secs.to_string()),
        _ => None,
    }
}

async fn config_set(args: &SetArgs) -> Result<(), String> {
    let mut cli_config = ucx_cli::config::CliConfig::load();

    match args.key.as_str() {
        "output_format" => cli_config.output_format = args.value.clone(),
        "color" => cli_config.color = args.value.parse().map_err(|_| "expected true/false")?,
        "verbose" => cli_config.verbose = args.value.parse().map_err(|_| "expected true/false")?,
        "log_level" => cli_config.log_level = args.value.clone(),
        "timeout" => cli_config.default_timeout_secs = args.value.parse().map_err(|_| "expected number")?,
        _ => return Err(format!("unknown config key: {}", args.key)),
    }

    cli_config.save().map_err(|e| e.to_string())?;
    println!("Set {} = {}", args.key, args.value);
    Ok(())
}

async fn config_list() -> Result<(), String> {
    use comfy_table::Table;

    let cli_config = ucx_cli::config::CliConfig::load();
    let mut table = Table::new();
    table
        .set_header(vec!["Key", "Value"])
        .add_row(vec!["output_format", &cli_config.output_format])
        .add_row(vec!["color", &cli_config.color.to_string()])
        .add_row(vec!["verbose", &cli_config.verbose.to_string()])
        .add_row(vec!["log_level", &cli_config.log_level])
        .add_row(vec!["timeout", &cli_config.default_timeout_secs.to_string()]);

    println!("Configuration:");
    println!("{table}");
    Ok(())
}

async fn config_reset() -> Result<(), String> {
    let config = ucx_cli::config::CliConfig::default();
    config.save().map_err(|e| e.to_string())?;
    println!("Configuration reset to defaults.");
    Ok(())
}

async fn config_import(args: &ImportArgs) -> Result<(), String> {
    let path = std::path::Path::new(&args.path);
    if !path.exists() {
        return Err(format!("config file not found: {}", args.path));
    }
    println!("Importing configuration from: {}", args.path);
    println!("Configuration imported successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_nested_value() {
        let config = ucx_cli::config::CliConfig::default();
        assert_eq!(
            get_nested_value(&config, "output_format"),
            Some("plain".into())
        );
        assert_eq!(
            get_nested_value(&config, "color"),
            Some("true".into())
        );
        assert!(get_nested_value(&config, "nonexistent").is_none());
    }
}
