//! zentinel-modsec CLI tool.

use clap::{Parser, Subcommand};
use zentinel_modsec::{ModSecurity, Result, Transaction};
use std::path::PathBuf;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "zentinel-modsec")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Increase logging verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check if rules parse correctly
    Check {
        /// Path to rules file or directory
        #[arg(short, long)]
        rules: PathBuf,
    },

    /// Test a request against rules
    Test {
        /// Path to rules file
        #[arg(short, long)]
        rules: PathBuf,

        /// Request URI
        #[arg(short, long)]
        uri: String,

        /// Request method
        #[arg(short, long, default_value = "GET")]
        method: String,

        /// Request headers (format: "Name: Value")
        #[arg(short = 'H', long)]
        header: Vec<String>,

        /// Request body
        #[arg(short, long)]
        body: Option<String>,
    },

    /// Print parsed rules
    Dump {
        /// Path to rules file
        #[arg(short, long)]
        rules: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    match cli.command {
        Commands::Check { rules } => check_rules(&rules),
        Commands::Test {
            rules,
            uri,
            method,
            header,
            body,
        } => test_request(&rules, &uri, &method, &header, body.as_deref()),
        Commands::Dump { rules } => dump_rules(&rules),
    }
}

fn check_rules(path: &PathBuf) -> Result<()> {
    info!("Checking rules from {:?}", path);

    let path_str = path.to_string_lossy();
    let modsec = ModSecurity::from_file(&path_str)?;

    println!("Successfully parsed {} rules", modsec.rule_count());
    Ok(())
}

fn test_request(
    rules_path: &PathBuf,
    uri: &str,
    method: &str,
    headers: &[String],
    body: Option<&str>,
) -> Result<()> {
    info!("Testing request against rules from {:?}", rules_path);

    let path_str = rules_path.to_string_lossy();
    let modsec = ModSecurity::from_file(&path_str)?;
    let mut tx = modsec.new_transaction();

    // Process URI
    tx.process_uri(uri, method, "HTTP/1.1")?;

    // Add headers
    for header in headers {
        if let Some((name, value)) = header.split_once(':') {
            tx.add_request_header(name.trim(), value.trim())?;
        }
    }

    // Process request headers
    tx.process_request_headers()?;

    // Check for intervention after phase 1
    if let Some(intervention) = tx.intervention() {
        println!("BLOCKED (Phase 1)");
        println!("  Status: {}", intervention.status);
        println!("  Rules: {:?}", intervention.rule_ids);
        if let Some(ref log) = intervention.log {
            println!("  Message: {}", log);
        }
        return Ok(());
    }

    // Process request body if provided
    if let Some(body_data) = body {
        tx.append_request_body(body_data.as_bytes())?;
        tx.process_request_body()?;

        if let Some(intervention) = tx.intervention() {
            println!("BLOCKED (Phase 2)");
            println!("  Status: {}", intervention.status);
            println!("  Rules: {:?}", intervention.rule_ids);
            if let Some(ref log) = intervention.log {
                println!("  Message: {}", log);
            }
            return Ok(());
        }
    }

    println!("ALLOWED");
    println!("  Matched rules: {:?}", tx.matched_rules());
    println!("  Anomaly score: {}", tx.anomaly_score());

    Ok(())
}

fn dump_rules(path: &PathBuf) -> Result<()> {
    info!("Dumping rules from {:?}", path);

    let path_str = path.to_string_lossy();
    let modsec = ModSecurity::from_file(&path_str)?;

    println!("Total rules: {}", modsec.rule_count());
    println!("\nRules by phase:");

    for phase_num in 1..=5 {
        if let Some(phase) = zentinel_modsec::engine::phase::Phase::from_number(phase_num) {
            let rules = modsec.ruleset().rules_for_phase(phase);
            if !rules.is_empty() {
                println!("\n  Phase {} ({}):", phase_num, phase.name());
                for rule in rules {
                    let id = rule.id.as_deref().unwrap_or("no-id");
                    println!("    - Rule {}", id);
                }
            }
        }
    }

    Ok(())
}
