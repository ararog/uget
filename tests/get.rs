use assert_cmd::Command;
use predicates::prelude::predicate;

#[test]
fn test_simple_get() {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("uget").unwrap();
    cmd.arg("https://httpbin.org/get");
    cmd.assert().success();
}

#[test]
fn test_simple_get_with_args() {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("uget").unwrap();
    cmd.arg("https://httpbin.org/get");
    cmd.arg("--method");
    cmd.arg("GET");
    cmd.arg("--header");
    cmd.arg("User-Agent: uget");
    cmd.assert().success();
}

#[test]
fn test_no_follow() {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("uget").unwrap();
    cmd.arg("https://uol.com");
    cmd.arg("--method");
    cmd.arg("GET");
    cmd.assert()
        .stdout(predicate::str::contains("301 Moved Permanently"));
}

#[test]
fn test_follow() {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("uget").unwrap();
    cmd.arg("https://uol.com");
    cmd.arg("--follow");
    cmd.arg("--method");
    cmd.arg("GET");
    cmd.assert().stdout(predicate::str::contains(
        "<title>UOL - Seu universo online</title>",
    ));
}
