use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn file_does_not_exist() -> Result<()> {
    let mut cmd = Command::cargo_bin("barrage")?;

    cmd.arg("foobar").arg("fake/test/file");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("No such file"));
    Ok(())
}
