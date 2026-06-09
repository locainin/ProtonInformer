//! Bounded helper process execution checks.

use std::collections::BTreeMap;
use std::path::PathBuf;

use proton_informer::helper;
use proton_informer::helper_executor::{execute, execute_in_directory};
use proton_informer::helper_runtime::{HelperInvocation, HelperRuntime};
use tempfile::tempdir;

/// Builds a typed invocation for one ordinary test command.
fn invocation(program: PathBuf, arguments: Vec<String>) -> HelperInvocation {
    HelperInvocation {
        arguments,
        environment: BTreeMap::new(),
        program,
        runtime: HelperRuntime::Wine {
            prefix: PathBuf::from("/unused"),
            wine_binary: PathBuf::from("/unused"),
        },
    }
}

#[test]
fn executor_captures_bounded_standard_output() {
    let printf = helper::find_command("printf").expect("printf command");
    let output = execute(&invocation(printf, vec!["hello".into()]), 1_000)
        .expect("successful command execution");

    assert_eq!(output.exit_code, Some(0));
    assert_eq!(output.stdout, "hello");
    assert!(output.stderr.is_empty());
}

#[test]
fn executor_terminates_a_timed_out_process() {
    let sleep = helper::find_command("sleep").expect("sleep command");
    let error =
        execute(&invocation(sleep, vec!["1".into()]), 10).expect_err("long command must time out");

    assert_eq!(error.kind(), "helper_timeout");
}

#[test]
fn executor_can_retain_private_run_output_for_diagnostics() {
    let directory = tempdir().expect("temporary directory");
    let printf = helper::find_command("printf").expect("printf command");

    let output = execute_in_directory(
        &invocation(printf, vec!["diagnostic".into()]),
        1_000,
        directory.path(),
        true,
    )
    .expect("successful command execution");

    assert_eq!(output.stdout, "diagnostic");
    assert!(directory.path().join("helper.stdout").is_file());
    assert!(directory.path().join("helper.stderr").is_file());
}

#[test]
fn executor_removes_run_output_when_retention_is_disabled() {
    let directory = tempdir().expect("temporary directory");
    let printf = helper::find_command("printf").expect("printf command");

    execute_in_directory(
        &invocation(printf, vec!["temporary".into()]),
        1_000,
        directory.path(),
        false,
    )
    .expect("successful command execution");

    assert!(!directory.path().join("helper.stdout").exists());
    assert!(!directory.path().join("helper.stderr").exists());
}

#[test]
fn executor_cleans_first_output_when_second_output_cannot_be_created() {
    let directory = tempdir().expect("temporary directory");
    std::fs::write(directory.path().join("helper.stderr"), b"occupied")
        .expect("existing stderr fixture");
    let printf = helper::find_command("printf").expect("printf command");

    execute_in_directory(
        &invocation(printf, vec!["unused".into()]),
        1_000,
        directory.path(),
        false,
    )
    .expect_err("existing stderr must stop execution");

    assert!(!directory.path().join("helper.stdout").exists());
    assert_eq!(
        std::fs::read(directory.path().join("helper.stderr")).expect("existing stderr"),
        b"occupied"
    );
}

#[test]
fn executor_clears_parent_environment_before_adding_explicit_values() {
    let env = helper::find_command("env").expect("env command");
    let mut command = invocation(env, Vec::new());
    command
        .environment
        .insert("PROTON_INFORMER_TEST".into(), "clean".into());

    let output = execute(&command, 1_000).expect("successful command execution");

    assert_eq!(output.stdout.trim(), "PROTON_INFORMER_TEST=clean");
    assert!(!output.stdout.contains("HOME="));
    assert!(!output.stdout.contains("CARGO"));
}
