use assert_cmd::Command;

#[test]
fn simple_post() {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("uget").unwrap();
    cmd.arg("https://httpbin.org/post");
    cmd.arg("--method");
    cmd.arg("POST");
    cmd.assert().success();
}

#[test]
fn post_from_stdin() {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("uget").unwrap();
    cmd.arg("https://jsonplaceholder.typicode.com/posts");
    cmd.write_stdin("{\"title\": \"foo\", \"body\": \"bar\", \"userId\": 1}");
    cmd.assert().success();
}
