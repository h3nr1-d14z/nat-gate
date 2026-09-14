use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;

#[test]
fn test_cli_no_args_shows_help() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn test_cli_help_flag() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Manage iptables port forwarding"));
}

#[test]
fn test_cli_version_flag() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("nat-gate"));
}

#[test]
fn test_add_invalid_protocol() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["add", "invalid", "80", "10.0.0.1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Protocol must be 'tcp' or 'udp'"));
}

#[test]
fn test_add_invalid_port_zero() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["add", "tcp", "0", "10.0.0.1"]).assert().failure();
}

#[test]
fn test_add_invalid_port_too_high() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["add", "tcp", "70000", "10.0.0.1"])
        .assert()
        .failure();
}

#[test]
fn test_add_invalid_ip() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["add", "tcp", "80", "not.an.ip.address"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid IP address"));
}

#[test]
fn test_add_invalid_ip_format() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["add", "tcp", "80", "256.0.0.1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid IP address"));
}

#[test]
fn test_del_invalid_protocol() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["del", "invalid", "80"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Protocol must be 'tcp' or 'udp'"));
}

#[test]
fn test_init_subcommand_exists() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    // This will fail due to not being root, but we're just checking the command exists
    cmd.arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("root").or(predicate::str::contains("sudo")));
}

#[test]
fn test_list_subcommand_exists() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    // This will fail due to not being root, but we're just checking the command exists
    cmd.arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("root").or(predicate::str::contains("sudo")));
}

// Tests for new v0.2.0 features

#[test]
fn test_dry_run_flag_recognized() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["--dry-run", "add", "tcp", "80", "10.0.0.1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[DRY-RUN]").or(predicate::str::contains("Would add")));
}

#[test]
fn test_dry_run_json_output() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["--dry-run", "--json", "add", "tcp", "80", "10.0.0.1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"dry_run\": true"));
}

#[test]
fn test_backup_help() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["backup", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Export nat-gate rules"));
}

#[test]
fn test_restore_help() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["restore", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Restore nat-gate rules"));
}

#[test]
fn test_restore_missing_file() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["--dry-run", "restore", "/nonexistent/file.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to read backup file"));
}

#[test]
fn test_apply_help() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["apply", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Apply rules from a YAML config file",
        ));
}

#[test]
fn test_apply_no_config_file() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["--dry-run", "apply"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("No config file found"));
}

#[test]
fn test_tailscale_help() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["tailscale", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("List available Tailscale peers"));
}

#[test]
fn test_status_help() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["status", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Show system status"));
}

#[test]
fn test_dry_run_init() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["--dry-run", "init"]).assert().success().stdout(
        predicate::str::contains("[DRY-RUN]").or(predicate::str::contains("Would initialize")),
    );
}

#[test]
fn test_dry_run_del() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["--dry-run", "del", "tcp", "80"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[DRY-RUN]").or(predicate::str::contains("Would delete")));
}

#[test]
fn test_port_range_validation() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["--dry-run", "add", "tcp", "8000-8080", "10.0.0.1"])
        .assert()
        .success();
}

#[test]
fn test_port_range_reversed_fails() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["add", "tcp", "8080-8000", "10.0.0.1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Start port must be less than"));
}

#[test]
fn test_port_range_too_large_fails() {
    let mut cmd = cargo_bin_cmd!("nat-gate");
    cmd.args(["add", "tcp", "1-2000", "10.0.0.1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Port range too large"));
}
