//! Process Utilities
//!
//! Provides process-related utility functions for Linux.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use crate::{EdrError, Result};

/// Memory region information from /proc/[pid]/maps
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Start address
    pub start: u64,
    /// End address
    pub end: u64,
    /// Permissions (rwxp)
    pub permissions: String,
    /// Offset
    pub offset: u64,
    /// Device
    pub device: String,
    /// Inode
    pub inode: u64,
    /// Pathname (if mapped file)
    pub pathname: Option<String>,
}

/// Get memory regions for a process
pub fn get_process_memory_regions(pid: i32) -> Result<Vec<MemoryRegion>> {
    let maps_path = format!("/proc/{pid}/maps");
    let file = File::open(&maps_path)
        .map_err(|e| EdrError::ProcessMonitor(format!("Failed to open {maps_path}: {e}")))?;

    let reader = BufReader::new(file);
    let mut regions = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if let Some(region) = parse_maps_line(&line) {
            regions.push(region);
        }
    }

    Ok(regions)
}

/// Parse a line from /proc/[pid]/maps
fn parse_maps_line(line: &str) -> Option<MemoryRegion> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.is_empty() {
        return None;
    }

    // Parse address range
    let addr_parts: Vec<&str> = parts[0].split('-').collect();
    if addr_parts.len() != 2 {
        return None;
    }

    let start = u64::from_str_radix(addr_parts[0], 16).ok()?;
    let end = u64::from_str_radix(addr_parts[1], 16).ok()?;

    let permissions = parts.get(1).map(|s| (*s).to_string()).unwrap_or_default();
    let offset = parts
        .get(2)
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let device = parts.get(3).map(|s| (*s).to_string()).unwrap_or_default();
    let inode = parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);

    let pathname = if parts.len() > 5 {
        Some(parts[5..].join(" "))
    } else {
        None
    };

    Some(MemoryRegion {
        start,
        end,
        permissions,
        offset,
        device,
        inode,
        pathname,
    })
}

/// Read memory from a specific region
pub fn read_memory_region(pid: i32, start: u64, size: usize) -> Result<Vec<u8>> {
    let mem_path = format!("/proc/{pid}/mem");
    let mut file = File::open(&mem_path)
        .map_err(|e| EdrError::ProcessMonitor(format!("Failed to open {mem_path}: {e}")))?;

    file.seek(SeekFrom::Start(start))
        .map_err(|e| EdrError::ProcessMonitor(format!("Failed to seek to 0x{start:x}: {e}")))?;

    let mut buffer = vec![0u8; size];
    let bytes_read = file.read(&mut buffer).map_err(|e| {
        EdrError::ProcessMonitor(format!("Failed to read memory at 0x{start:x}: {e}"))
    })?;

    buffer.truncate(bytes_read);
    Ok(buffer)
}

/// Read all readable process memory
pub fn read_process_memory(pid: i32) -> Result<Vec<u8>> {
    let regions = get_process_memory_regions(pid)?;
    let mut all_memory = Vec::new();

    // Limit total memory to prevent OOM
    const MAX_MEMORY: usize = 100 * 1024 * 1024; // 100 MB

    for region in regions {
        // Only read readable, non-shared memory
        if !region.permissions.contains('r') {
            continue;
        }

        // Skip certain regions
        if let Some(pathname) = &region.pathname {
            // Skip stack, heap markers, and special mappings
            if pathname == "[vvar]" || pathname == "[vdso]" || pathname == "[vsyscall]" {
                continue;
            }
        }

        let size = (region.end - region.start) as usize;

        // Skip very large regions
        if size > 10 * 1024 * 1024 {
            continue;
        }

        if let Ok(data) = read_memory_region(pid, region.start, size) {
            all_memory.extend(data);

            if all_memory.len() > MAX_MEMORY {
                break;
            }
        }
    }

    Ok(all_memory)
}

/// Get process executable path
pub fn get_process_exe(pid: i32) -> Result<PathBuf> {
    let exe_path = format!("/proc/{pid}/exe");
    fs::read_link(&exe_path).map_err(|e| {
        EdrError::ProcessMonitor(format!("Failed to read exe link for PID {pid}: {e}"))
    })
}

/// Get process command line
pub fn get_process_cmdline(pid: i32) -> Result<String> {
    let cmdline_path = format!("/proc/{pid}/cmdline");
    let content = fs::read(&cmdline_path).map_err(|e| {
        EdrError::ProcessMonitor(format!("Failed to read cmdline for PID {pid}: {e}"))
    })?;

    // Command line arguments are separated by null bytes
    let cmdline = content
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect::<Vec<_>>()
        .join(" ");

    Ok(cmdline)
}

/// Get process environment variables
pub fn get_process_environ(pid: i32) -> Result<Vec<(String, String)>> {
    let environ_path = format!("/proc/{pid}/environ");
    let content = fs::read(&environ_path).map_err(|e| {
        EdrError::ProcessMonitor(format!("Failed to read environ for PID {pid}: {e}"))
    })?;

    let mut env_vars = Vec::new();

    for var in content.split(|&b| b == 0) {
        if var.is_empty() {
            continue;
        }

        let var_str = String::from_utf8_lossy(var);
        if let Some(eq_pos) = var_str.find('=') {
            let key = var_str[..eq_pos].to_string();
            let value = var_str[eq_pos + 1..].to_string();
            env_vars.push((key, value));
        }
    }

    Ok(env_vars)
}

/// Get parent PID
pub fn get_ppid(pid: i32) -> Result<i32> {
    let process = procfs::process::Process::new(pid)
        .map_err(|e| EdrError::ProcessMonitor(format!("Failed to get process {pid}: {e}")))?;

    let stat = process
        .stat()
        .map_err(|e| EdrError::ProcessMonitor(format!("Failed to get stat for {pid}: {e}")))?;

    Ok(stat.ppid)
}

/// Get all child PIDs
pub fn get_child_pids(pid: i32) -> Result<Vec<i32>> {
    let mut children = Vec::new();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if let Ok(child_pid) = name.parse::<i32>()
            && let Ok(ppid) = get_ppid(child_pid)
            && ppid == pid
        {
            children.push(child_pid);
        }
    }

    Ok(children)
}

/// Check if process is running
pub fn is_process_running(pid: i32) -> bool {
    PathBuf::from(format!("/proc/{pid}")).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_maps_line() {
        let line = "7f8b8c000000-7f8b8c021000 rw-p 00000000 00:00 0";
        let region = parse_maps_line(line).unwrap();

        assert_eq!(region.start, 0x7f8b8c000000);
        assert_eq!(region.end, 0x7f8b8c021000);
        assert_eq!(region.permissions, "rw-p");
    }

    #[test]
    fn test_parse_maps_line_with_path() {
        let line = "7f8b8c000000-7f8b8c021000 r-xp 00000000 08:01 123456 /usr/lib/libc.so.6";
        let region = parse_maps_line(line).unwrap();

        assert_eq!(region.pathname, Some("/usr/lib/libc.so.6".to_string()));
    }

    #[test]
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
}
