use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kmodguard_core::{
    DEFAULT_DAEMON_SOCKET_PATH, DEFAULT_HANDLER_PATH, DEFAULT_ORIGINAL_MODPROBE_PATH,
    DEFAULT_POLICY_PATH, baseline_policy, kernel_release, save_policy,
};
use syslog::{Facility, Formatter3164};

const DEFAULT_DAEMON_PATH: &str = "/usr/libexec/kmodguard/kmodguard";
const DEFAULT_DAEMON_PID_PATH: &str = "/run/kmodguard/daemon.pid";

#[derive(Debug, Parser)]
#[command(name = "kmodctl", about = "kmodguard helper CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Init {
        #[arg(long, default_value = DEFAULT_POLICY_PATH)]
        output: String,
    },
    Start {
        #[arg(long, default_value = DEFAULT_POLICY_PATH)]
        policy: String,
        #[arg(long, default_value = DEFAULT_HANDLER_PATH)]
        handler: String,
        #[arg(long, default_value = DEFAULT_ORIGINAL_MODPROBE_PATH)]
        original_modprobe_state: String,
        #[arg(long, default_value = DEFAULT_DAEMON_PATH)]
        daemon: String,
        #[arg(long, default_value = DEFAULT_DAEMON_SOCKET_PATH)]
        socket: String,
        #[arg(long, default_value = DEFAULT_DAEMON_PID_PATH)]
        daemon_pid_file: String,
    },
    Stop {
        #[arg(long, default_value = DEFAULT_ORIGINAL_MODPROBE_PATH)]
        original_modprobe_state: String,
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(long, default_value = DEFAULT_DAEMON_PID_PATH)]
        daemon_pid_file: String,
    },
    Status {
        #[arg(long, default_value = DEFAULT_ORIGINAL_MODPROBE_PATH)]
        original_modprobe_state: String,
    },
    Hook {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        hook_args: Vec<String>,
        #[arg(long, default_value = DEFAULT_DAEMON_SOCKET_PATH)]
        socket: String,
    },
    Allow {
        module: String,
        #[arg(long, default_value = DEFAULT_DAEMON_SOCKET_PATH)]
        socket: String,
    },
    Remove {
        module: String,
        #[arg(long, default_value = DEFAULT_DAEMON_SOCKET_PATH)]
        socket: String,
    },
    Apply {
        #[arg(long, default_value = DEFAULT_DAEMON_SOCKET_PATH)]
        socket: String,
    },
    Arm {
        #[arg(long, default_value = DEFAULT_POLICY_PATH)]
        policy: String,
        #[arg(long, default_value = DEFAULT_HANDLER_PATH)]
        handler: String,
        #[arg(long, default_value = DEFAULT_ORIGINAL_MODPROBE_PATH)]
        original_modprobe_state: String,
    },
    Disarm {
        #[arg(long, default_value = DEFAULT_ORIGINAL_MODPROBE_PATH)]
        original_modprobe_state: String,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { output } => cmd_init(&output),
        Commands::Start {
            policy,
            handler,
            original_modprobe_state,
            daemon,
            socket,
            daemon_pid_file,
        } => cmd_start(
            &policy,
            &handler,
            &original_modprobe_state,
            &daemon,
            &socket,
            &daemon_pid_file,
        ),
        Commands::Stop {
            original_modprobe_state,
            force,
            daemon_pid_file,
        } => cmd_stop(&original_modprobe_state, force, &daemon_pid_file),
        Commands::Status {
            original_modprobe_state,
        } => cmd_status(&original_modprobe_state),
        Commands::Hook { hook_args, socket } => cmd_hook(&hook_args, &socket),
        Commands::Allow { module, socket } => cmd_control(&socket, &format!("ALLOW {module}")),
        Commands::Remove { module, socket } => cmd_control(&socket, &format!("REMOVE {module}")),
        Commands::Apply { socket } => cmd_control(&socket, "APPLY"),
        Commands::Arm {
            policy,
            handler,
            original_modprobe_state,
        } => cmd_arm(&policy, &handler, &original_modprobe_state),
        Commands::Disarm {
            original_modprobe_state,
            force,
        } => cmd_disarm(&original_modprobe_state, force),
    }
}

fn cmd_init(output: &str) -> Result<()> {
    let kernel = kernel_release().context("read kernel release")?;
    let policy = baseline_policy(&kernel).context("build baseline policy")?;
    save_policy(Path::new(output), &policy).with_context(|| format!("write policy {output}"))?;
    println!("initial policy written to {output}");
    Ok(())
}

fn cmd_start(
    policy: &str,
    handler: &str,
    state_path: &str,
    daemon_path: &str,
    socket: &str,
    daemon_pid_file: &str,
) -> Result<()> {
    cmd_arm(policy, handler, state_path)?;
    let systemd_start = Command::new("systemctl")
        .args(["restart", "kmodguard.service"])
        .status();

    match systemd_start {
        Ok(status) if status.success() => {
            println!("kmodguard started by systemd; handler set to {handler}");
            Ok(())
        }
        _ => start_manual_daemon(policy, state_path, daemon_path, socket, daemon_pid_file),
    }
}

fn cmd_stop(state_path: &str, force: bool, daemon_pid_file: &str) -> Result<()> {
    let systemctl_stop = Command::new("systemctl")
        .args(["stop", "kmodguard.service"])
        .status();

    match systemctl_stop {
        Ok(status) if status.success() => {
            println!("kmodguard stopped by systemd");
            Ok(())
        }
        _ => {
            stop_manual_daemon(daemon_pid_file);
            cmd_disarm(state_path, force)
        }
    }
}

fn start_manual_daemon(
    policy: &str,
    state_path: &str,
    daemon_path: &str,
    socket: &str,
    daemon_pid_file: &str,
) -> Result<()> {
    if let Some(parent) = Path::new(daemon_pid_file).parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }

    if let Ok(existing_pid) = fs::read_to_string(daemon_pid_file) {
        let existing_pid = existing_pid.trim();
        if !existing_pid.is_empty() {
            let status = Command::new("kill").args(["-0", existing_pid]).status();
            if let Ok(s) = status {
                if s.success() {
                    println!("kmodguard already running (pid {existing_pid})");
                    return Ok(());
                }
            }
        }
    }

    let child = Command::new(daemon_path)
        .args([
            "--policy",
            policy,
            "--socket",
            socket,
            "--original-modprobe-state",
            state_path,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn daemon {daemon_path}"))?;
    fs::write(daemon_pid_file, format!("{}\n", child.id()))
        .with_context(|| format!("write daemon pid file {daemon_pid_file}"))?;

    println!(
        "kmodguard started without systemd (pid {}), handler is armed",
        child.id()
    );
    Ok(())
}

fn stop_manual_daemon(daemon_pid_file: &str) {
    let pid = match fs::read_to_string(daemon_pid_file) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return,
    };
    if pid.is_empty() {
        return;
    }
    let _ = Command::new("kill").arg(&pid).status();
    let _ = fs::remove_file(daemon_pid_file);
}

fn cmd_arm(policy: &str, handler: &str, state_path: &str) -> Result<()> {
    if !Path::new(policy).exists() {
        anyhow::bail!("policy file not found at {policy}; run 'kmodctl init' first");
    }

    let current = fs::read_to_string("/proc/sys/kernel/modprobe")
        .context("read /proc/sys/kernel/modprobe")?
        .trim()
        .to_string();
    if let Some(parent) = Path::new(state_path).parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }

    init_state_file(state_path, &current).with_context(|| format!("write {state_path}"))?;
    fs::set_permissions(state_path, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("chmod {state_path}"))?;

    fs::write("/proc/sys/kernel/modprobe", format!("{handler}\n"))
        .context("switch kernel modprobe handler")?;
    println!("kmodguard armed; handler set to {handler}");
    Ok(())
}

fn init_state_file(state_path: &str, current_handler: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(state_path)
    {
        Ok(mut file) => {
            file.write_all(format!("{current_handler}\n").as_bytes())?;
            file.sync_all()?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err),
    }
}

fn cmd_disarm(state_path: &str, force: bool) -> Result<()> {
    let original = read_saved_handler(state_path, force)?;
    fs::write("/proc/sys/kernel/modprobe", format!("{original}\n"))
        .context("restore kernel modprobe handler")?;
    let _ = fs::remove_file(state_path);
    println!("kmodguard disarmed; handler restored to {original}");
    Ok(())
}

fn read_saved_handler(state_path: &str, force: bool) -> Result<String> {
    match fs::read_to_string(state_path) {
        Ok(value) => Ok(value.trim().to_string()),
        Err(err) if force => {
            eprintln!("state read failed ({err}); forcing default /usr/bin/modprobe restore");
            Ok("/usr/bin/modprobe".to_string())
        }
        Err(err) => Err(err).with_context(|| format!("read state {state_path}")),
    }
}

fn cmd_status(state_path: &str) -> Result<()> {
    let current = fs::read_to_string("/proc/sys/kernel/modprobe")
        .context("read /proc/sys/kernel/modprobe")?
        .trim()
        .to_string();
    println!("current handler: {current}");

    if let Ok(saved) = fs::read_to_string(state_path) {
        println!("saved original handler: {}", saved.trim());
    } else {
        println!("saved original handler: <none>");
    }

    if let Ok(output) = Command::new("systemctl")
        .args(["is-active", "kmodguard.service"])
        .output()
    {
        print!(
            "service status: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    Ok(())
}

fn cmd_hook(hook_args: &[String], socket: &str) -> Result<()> {
    let token = extract_token(hook_args).context("extract module token")?;
    match forward_to_daemon(token, socket) {
        Ok(true) => Ok(()),
        Ok(false) => {
            audit(
                "warning",
                &format!("kmodguard denied (daemon unavailable): token={token} socket={socket}"),
            );
            anyhow::bail!("module load denied: kmodguard daemon unavailable at {socket}");
        }
        Err(err) => {
            audit(
                "warning",
                &format!("kmodguard daemon error: token={token} err={err:#}"),
            );
            Err(err).context("forward to daemon")
        }
    }
}

fn cmd_control(socket: &str, command: &str) -> Result<()> {
    let mut stream =
        UnixStream::connect(socket).with_context(|| format!("connect daemon socket {socket}"))?;
    stream
        .write_all(format!("{command}\n").as_bytes())
        .with_context(|| format!("send control command '{command}'"))?;
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line).context("read daemon reply")?;
    let line = line.trim();
    if line.starts_with("OK") {
        println!("{line}");
        Ok(())
    } else {
        anyhow::bail!("{line}");
    }
}

fn forward_to_daemon(token: &str, socket: &str) -> Result<bool> {
    let mut stream = match UnixStream::connect(socket) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    stream
        .write_all(format!("{token}\n").as_bytes())
        .context("send request to daemon")?;
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line).context("read daemon reply")?;
    if line.starts_with("OK") {
        return Ok(true);
    }
    anyhow::bail!("{}", line.trim());
}

fn extract_token(args: &[String]) -> Result<&str> {
    if args.is_empty() {
        anyhow::bail!("hook received no arguments");
    }
    if let Some(idx) = args.iter().position(|arg| arg == "--") {
        if let Some(module) = args.get(idx + 1) {
            return Ok(module.as_str());
        }
    }
    if let Some(last_non_option) = args.iter().rev().find(|arg| !arg.starts_with('-')) {
        return Ok(last_non_option.as_str());
    }
    anyhow::bail!("could not identify module token from hook arguments: {args:?}")
}

fn audit(severity: &str, message: &str) {
    let formatter = Formatter3164 {
        facility: Facility::LOG_AUTHPRIV,
        hostname: None,
        process: "kmodctl".into(),
        pid: std::process::id(),
    };
    if let Ok(mut writer) = syslog::unix(formatter) {
        match severity {
            "warning" => {
                let _ = writer.warning(message);
            }
            _ => {
                let _ = writer.info(message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{cmd_hook, extract_token, init_state_file, read_saved_handler};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_file(name: &str) -> String {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        format!("/tmp/{name}-{ts}")
    }

    #[test]
    fn stop_uses_saved_handler_when_present() {
        let path = tmp_file("kmodguard-state");
        fs::write(&path, "/usr/bin/modprobe\n").expect("write");
        let handler = read_saved_handler(&path, false).expect("handler");
        assert_eq!(handler, "/usr/bin/modprobe");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stop_force_falls_back_when_state_missing() {
        let path = tmp_file("kmodguard-state-missing");
        let handler = read_saved_handler(&path, true).expect("handler");
        assert_eq!(handler, "/usr/bin/modprobe");
    }

    #[test]
    fn extract_token_from_kernel_style_args() {
        let args = vec![
            "-q".to_string(),
            "--".to_string(),
            "nf_conntrack".to_string(),
        ];
        assert_eq!(extract_token(&args).expect("token"), "nf_conntrack");
    }

    #[test]
    fn hook_fails_closed_when_daemon_unreachable() {
        let socket = tmp_file("kmodguard-missing-sock");
        let args = vec!["--".to_string(), "loop".to_string()];
        let err = cmd_hook(&args, &socket).expect_err("hook must deny without daemon");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("denied") || msg.contains("unavailable"),
            "expected denial message, got: {msg}"
        );
    }

    #[test]
    fn init_state_preserves_existing_snapshot() {
        let path = tmp_file("kmodguard-arm-state");
        fs::write(&path, "/usr/bin/modprobe\n").expect("seed state");
        init_state_file(&path, "/tmp/handler-x").expect("init_state_file");
        let after = fs::read_to_string(&path).expect("read state");
        assert_eq!(after.trim(), "/usr/bin/modprobe");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn init_state_creates_when_absent() {
        let path = tmp_file("kmodguard-arm-state-new");
        init_state_file(&path, "/usr/bin/modprobe").expect("init_state_file");
        let content = fs::read_to_string(&path).expect("read state");
        assert_eq!(content.trim(), "/usr/bin/modprobe");
        let mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "expected 0644, got {mode:o}");
        let _ = fs::remove_file(path);
    }
}
