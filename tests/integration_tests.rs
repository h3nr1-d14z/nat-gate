use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_no_args_shows_help() {
    let mut cmd = Command::cargo_bin("nat-gate").unwrap();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn test_cli_help_flag() {
    let mut cmd = Command::cargo_bin("nat-gate").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Manage iptables port forwarding"));
}

#[test]
fn test_cli_version_flag() {
    let mut cmd = Command::cargo_bin("nat-gate").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("nat-gate"));
}

#[test]
fn test_add_invalid_protocol() {
    let mut cmd = Command::cargo_bin("nat-gate").unwrap();
    cmd.args(["add", "invalid", "80", "10.0.0.1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Protocol must be 'tcp' or 'udp'"));
}

#[test]
fn test_add_invalid_port_zero() {
    let mut cmd = Command::cargo_bin("nat-gate").unwrap();
    cmd.args(["add", "tcp", "0", "10.0.0.1"])
        .assert()
        .failure();
}

#[test]
fn test_add_invalid_port_too_high() {
    let mut cmd = Command::cargo_bin("nat-gate").unwrap();
    cmd.args(["add", "tcp", "70000", "10.0.0.1"])
        .assert()
        .failure();
}

#[test]
fn test_add_invalid_ip() {
    let mut cmd = Command::cargo_bin("nat-gate").unwrap();
    cmd.args(["add", "tcp", "80", "not.an.ip.address"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid IP address"));
}

#[test]
fn test_add_invalid_ip_format() {
    let mut cmd = Command::cargo_bin("nat-gate").unwrap();
    cmd.args(["add", "tcp", "80", "256.0.0.1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid IP address"));
}

#[test]
fn test_del_invalid_protocol() {
    let mut cmd = Command::cargo_bin("nat-gate").unwrap();
    cmd.args(["del", "invalid", "80"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Protocol must be 'tcp' or 'udp'"));
}

#[test]
fn test_init_subcommand_exists() {
    let mut cmd = Command::cargo_bin("nat-gate").unwrap();
    // This will fail due to not being root, but we're just checking the command exists
    cmd.arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("root").or(predicate::str::contains("sudo")));
}

#[test]
fn test_list_subcommand_exists() {
    let mut cmd = Command::cargo_bin("nat-gate").unwrap();
    // This will fail due to not being root, but we're just checking the command exists
    cmd.arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("root").or(predicate::str::contains("sudo")));
}
