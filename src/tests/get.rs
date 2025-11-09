use assert_cmd::Command;

#[test]
fn simple_get() {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("uget").unwrap();
    cmd.arg("https://httpbin.org/get");
    cmd.assert().success();
}

#[test]
fn simple_get_with_args() {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("uget").unwrap();
    cmd.arg("https://httpbin.org/get");
    cmd.arg("--method");
    cmd.arg("GET");
    cmd.arg("--header");
    cmd.arg("User-Agent: uget");
    cmd.assert().success();
}
