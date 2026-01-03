//! Unit tests for process utilities.

#![allow(clippy::unwrap_used)]

use yara_edr::utils::{get_process_cmdline, get_process_exe, is_process_running, parse_maps_line};

#[test]
fn test_parse_maps_line() {
    let line = "7f8b8c000000-7f8b8c021000 rw-p 00000000 00:00 0";
    let region = parse_maps_line(line).unwrap();

    assert_eq!(region.start, 0x7f8b_8c00_0000);
    assert_eq!(region.end, 0x7f8b_8c02_1000);
    assert_eq!(region.permissions, "rw-p");
}

#[test]
fn test_parse_maps_line_with_path() {
    let line = "7f8b8c000000-7f8b8c021000 r-xp 00000000 08:01 123456 /usr/lib/libc.so.6";
    let region = parse_maps_line(line).unwrap();

    assert_eq!(region.pathname, Some("/usr/lib/libc.so.6".to_string()));
}

#[test]
#[allow(clippy::cast_possible_wrap)]
fn test_current_process() {
    let pid = std::process::id() as i32;

    // Test getting exe
    let exe = get_process_exe(pid);
    assert!(exe.is_ok());

    // Test getting cmdline
    let cmdline = get_process_cmdline(pid);
    assert!(cmdline.is_ok());

    // Test process is running
    assert!(is_process_running(pid));
}

#[test]
fn test_nonexistent_process() {
    // PID 0 is the scheduler, we can use a very high PID that likely doesn't exist
    let fake_pid = 999_999_999;
    assert!(!is_process_running(fake_pid));
}

#[test]
fn test_parse_maps_line_no_path() {
    let line = "7f8b8c000000-7f8b8c021000 rw-p 00000000 00:00 0                          ";
    let region = parse_maps_line(line).unwrap();

    assert!(region.pathname.as_ref().is_none_or(String::is_empty));
}
