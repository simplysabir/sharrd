// tests/cli_tests.rs

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_version() {
    let mut cmd = Command::cargo_bin("shard").unwrap();
    cmd.arg("--version").assert().success().stdout(predicate::str::contains("shard"));
}

#[test]
fn test_init_help() {
    let mut cmd = Command::cargo_bin("shard").unwrap();
    cmd.arg("init").arg("--help").assert().success();
}

#[test]
fn test_list_missing_config() {
    let mut cmd = Command::cargo_bin("shard").unwrap();
    
    // The list command should trigger first-time setup
    // We don't actually want to run the interactive setup, just check that it's detected
    cmd.arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("Welcome to Shard!"));
}

// Note: More extensive tests would require mocking the interactive CLI,
// which is complex and may be better handled with manual testing or by
// creating a non-interactive test mode in the application.