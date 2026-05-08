use std::fs;
use std::fs::Metadata;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;

use anyhow::{Context, Result};
use clap::Parser;
use kmodguard_core::{
    CompiledPolicy, DEFAULT_DAEMON_SOCKET_PATH, DEFAULT_ORIGINAL_MODPROBE_PATH,
    DEFAULT_POLICY_PATH, Decision, FALLBACK_MODPROBE, ModuleResolver, Policy, allow_module, decide,
    kernel_release, remove_module, save_policy_atomic,
};
use syslog::{Facility, Formatter3164};

#[derive(Debug, Parser)]
#[command(name = "kmodguard", about = "kmodguard daemon")]
struct Args {
    #[arg(long, default_value = DEFAULT_POLICY_PATH)]
    policy: String,
    #[arg(long, default_value = DEFAULT_DAEMON_SOCKET_PATH)]
    socket: String,
    #[arg(long, default_value = DEFAULT_ORIGINAL_MODPROBE_PATH)]
    original_modprobe_state: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut state = DaemonState::load(&args)?;
    run_server(&args, &mut state)
}

#[derive(Debug, Clone)]
struct PolicyStamp {
    modified: Option<SystemTime>,
    len: u64,
}

struct DecisionLogger {
    formatter: Formatter3164,
}

impl DecisionLogger {
    fn new() -> Self {
        Self {
            formatter: Formatter3164 {
                facility: Facility::LOG_AUTHPRIV,
                hostname: None,
                process: "kmodguard".into(),
                pid: std::process::id(),
            },
        }
    }

    fn log(&self, kind: &str, decision: &Decision) {
        let message = format!(
            "kmodguard {kind}: token={} resolved={:?} reason={}",
            decision.token, decision.resolved_modules, decision.reason
        );
        eprintln!("{message}");
        if let Ok(mut writer) = syslog::unix(self.formatter.clone()) {
            match kind {
                "deny" => {
                    let _ = writer.warning(&message);
                }
                _ => {
                    let _ = writer.info(&message);
                }
            }
        }
    }

    fn log_control(&self, action: &str, detail: &str) {
        let message = format!("kmodguard control {action}: {detail}");
        eprintln!("{message}");
        if let Ok(mut writer) = syslog::unix(self.formatter.clone()) {
            let _ = writer.info(&message);
        }
    }
}

struct DaemonState {
    policy_path: String,
    policy_stamp: PolicyStamp,
    policy: Policy,
    compiled_policy: CompiledPolicy,
    resolver: ModuleResolver,
    logger: DecisionLogger,
    dirty: bool,
    modprobe_path: String,
}

impl DaemonState {
    fn load(args: &Args) -> Result<Self> {
        let mut file = fs::File::open(&args.policy)
            .with_context(|| format!("loading policy {}", args.policy))?;
        let policy_stamp = stamp_from_meta(
            &file
                .metadata()
                .with_context(|| format!("stat policy {}", args.policy))?,
        );
        let mut content = String::new();
        file.read_to_string(&mut content)
            .with_context(|| format!("read policy {}", args.policy))?;
        let policy: Policy =
            toml::from_str(&content).with_context(|| format!("parse policy {}", args.policy))?;
        let kernel = kernel_release().context("kernel release")?;
        let resolver = ModuleResolver::new(&kernel).context("resolver build")?;
        let modprobe_path = read_modprobe_state(&args.original_modprobe_state);

        Ok(Self {
            policy_path: args.policy.clone(),
            policy_stamp,
            policy: policy.clone(),
            compiled_policy: CompiledPolicy::from_policy(&policy),
            resolver,
            logger: DecisionLogger::new(),
            dirty: false,
            modprobe_path,
        })
    }

    fn maybe_reload_policy(&mut self) -> Result<()> {
        if self.dirty {
            return Ok(());
        }

        let mut file = match fs::File::open(&self.policy_path) {
            Ok(f) => f,
            Err(err) => {
                eprintln!("kmodguard policy open failed: {err}");
                return Ok(());
            }
        };
        let meta = match file.metadata() {
            Ok(m) => m,
            Err(err) => {
                eprintln!("kmodguard policy metadata check failed: {err}");
                return Ok(());
            }
        };
        let new_stamp = stamp_from_meta(&meta);
        if stamps_equal(&self.policy_stamp, &new_stamp) {
            return Ok(());
        }

        let mut content = String::new();
        if let Err(err) = file.read_to_string(&mut content) {
            eprintln!("kmodguard policy read failed; keeping previous policy: {err}");
            return Ok(());
        }

        match toml::from_str::<Policy>(&content) {
            Ok(policy) => {
                self.policy = policy.clone();
                self.compiled_policy = CompiledPolicy::from_policy(&policy);
                self.policy_stamp = new_stamp;
                eprintln!("kmodguard policy cache reloaded");
            }
            Err(err) => {
                eprintln!("kmodguard policy reload failed; keeping previous policy: {err}");
            }
        }
        Ok(())
    }
}

fn read_modprobe_state(state_path: &str) -> String {
    fs::read_to_string(state_path)
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| FALLBACK_MODPROBE.to_string())
}

fn stamp_from_meta(meta: &Metadata) -> PolicyStamp {
    PolicyStamp {
        modified: meta.modified().ok(),
        len: meta.len(),
    }
}

fn stamps_equal(a: &PolicyStamp, b: &PolicyStamp) -> bool {
    a.len == b.len && a.modified == b.modified
}

fn run_server(args: &Args, state: &mut DaemonState) -> Result<()> {
    let socket_path = Path::new(&args.socket);
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating socket parent {}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("locking down socket parent {}", parent.display()))?;
    }

    match fs::remove_file(socket_path) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(anyhow::Error::new(err))
                .with_context(|| format!("removing stale socket {}", socket_path.display()));
        }
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding socket {}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting socket {}", socket_path.display()))?;
    eprintln!("kmodguard listening on {}", socket_path.display());

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(err) = handle_connection(stream, state) {
                    eprintln!("kmodguard request error: {err:#}");
                }
            }
            Err(err) => eprintln!("kmodguard accept error: {err}"),
        }
    }
    Ok(())
}

fn handle_connection(mut stream: UnixStream, state: &mut DaemonState) -> Result<()> {
    if let Err(err) = require_root(&stream) {
        let _ = stream.write_all(b"ERR unauthorized\n");
        state.logger.log_control("reject", &format!("{err}"));
        return Ok(());
    }

    let mut line = String::new();
    let mut reader = BufReader::new(stream.try_clone().context("clone stream")?);
    reader.read_line(&mut line).context("read token")?;
    let request = line.trim();
    if request.is_empty() {
        stream
            .write_all(b"ERR empty token\n")
            .context("write error")?;
        return Ok(());
    }

    state.maybe_reload_policy()?;
    let response = process_request(request, state)?;
    stream
        .write_all(response.as_bytes())
        .context("write reply")?;
    Ok(())
}

fn require_root(stream: &UnixStream) -> Result<()> {
    let cred = rustix::net::sockopt::socket_peercred(stream.as_fd())
        .context("read peer credentials")?;
    let uid = cred.uid.as_raw();
    if uid != 0 {
        anyhow::bail!("unauthorized peer uid={uid}");
    }
    Ok(())
}

fn process_request(request: &str, state: &mut DaemonState) -> Result<String> {
    let mut parts = request.split_whitespace();
    let head = parts.next().unwrap_or_default();
    let command = head.to_ascii_uppercase();

    if command != "CHECK" && command != "ALLOW" && command != "REMOVE" && command != "APPLY" {
        return check_and_load(request, state);
    }

    match command.as_str() {
        "CHECK" => {
            let token = parts.next().context("missing CHECK token")?;
            check_and_load(token, state)
        }
        "ALLOW" => {
            let module = parts.next().context("missing ALLOW module")?;
            let changed = allow_module(&mut state.policy, module);
            if changed {
                state.compiled_policy = CompiledPolicy::from_policy(&state.policy);
                state.dirty = true;
            }
            state
                .logger
                .log_control("allow", &format!("module={module} changed={changed}"));
            Ok(format!("OK allow module={module} changed={changed}\n"))
        }
        "REMOVE" => {
            let module = parts.next().context("missing REMOVE module")?;
            let changed = remove_module(&mut state.policy, module);
            if changed {
                state.compiled_policy = CompiledPolicy::from_policy(&state.policy);
                state.dirty = true;
            }
            state
                .logger
                .log_control("remove", &format!("module={module} changed={changed}"));
            Ok(format!("OK remove module={module} changed={changed}\n"))
        }
        "APPLY" => {
            save_policy_atomic(Path::new(&state.policy_path), &state.policy)
                .context("persist runtime policy")?;
            let policy_meta = fs::metadata(&state.policy_path)
                .with_context(|| format!("read metadata {}", state.policy_path))?;
            state.policy_stamp = stamp_from_meta(&policy_meta);
            state.dirty = false;
            state
                .logger
                .log_control("apply", "runtime policy persisted");
            Ok("OK apply persisted\n".to_string())
        }
        _ => Ok("ERR unsupported command\n".to_string()),
    }
}

fn check_and_load(token: &str, state: &DaemonState) -> Result<String> {
    let decision = decide(&state.compiled_policy, &state.resolver, token);
    if decision.allowed {
        run_modprobe(token, &state.modprobe_path)?;
        state.logger.log("allow", &decision);
        Ok("OK\n".to_string())
    } else {
        state.logger.log("deny", &decision);
        Ok(format!("DENY {}\n", decision.reason))
    }
}

fn run_modprobe(token: &str, modprobe_path: &str) -> Result<()> {
    let status = Command::new(modprobe_path)
        .arg(token)
        .status()
        .with_context(|| format!("exec {modprobe_path} {token}"))?;
    if !status.success() {
        anyhow::bail!("modprobe command failed with status {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use kmodguard_core::{AllowList, DenyList, Policy, PolicyMode};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_path(name: &str) -> String {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        format!("/tmp/{name}-{ts}.toml")
    }

    fn test_state(path: &str) -> DaemonState {
        let policy = Policy {
            version: 1,
            generated_at: Utc::now(),
            kernel_release: "test".to_string(),
            mode: PolicyMode::Enforce,
            allow: AllowList {
                modules: vec!["loop".to_string()],
                aliases: vec![],
            },
            deny: DenyList::default(),
        };
        DaemonState {
            policy_path: path.to_string(),
            policy_stamp: PolicyStamp {
                modified: None,
                len: 0,
            },
            policy: policy.clone(),
            compiled_policy: CompiledPolicy::from_policy(&policy),
            resolver: ModuleResolver::from_parts(vec!["loop".to_string()], vec![])
                .expect("resolver"),
            logger: DecisionLogger::new(),
            dirty: false,
            modprobe_path: FALLBACK_MODPROBE.to_string(),
        }
    }

    #[test]
    fn allow_and_remove_toggle_dirty_state() {
        let path = tmp_path("kmodguard-policy");
        let mut state = test_state(&path);
        let allow = process_request("ALLOW dm_mod", &mut state).expect("allow");
        assert!(allow.starts_with("OK allow"));
        assert!(state.dirty);
        assert!(state.policy.allow.modules.iter().any(|m| m == "dm_mod"));

        let remove = process_request("REMOVE dm_mod", &mut state).expect("remove");
        assert!(remove.starts_with("OK remove"));
        assert!(!state.policy.allow.modules.iter().any(|m| m == "dm_mod"));
    }

    #[test]
    fn apply_persists_runtime_policy() {
        let path = tmp_path("kmodguard-policy-apply");
        let mut state = test_state(&path);
        let _ = process_request("ALLOW dm_mod", &mut state).expect("allow");
        let apply = process_request("APPLY", &mut state).expect("apply");
        assert!(apply.starts_with("OK apply"));
        assert!(!state.dirty);
        let saved = fs::read_to_string(&path).expect("saved policy");
        assert!(saved.contains("dm_mod"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn read_modprobe_state_falls_back_when_missing() {
        let path = tmp_path("kmodguard-state-missing");
        let snap = read_modprobe_state(&path);
        assert_eq!(snap, FALLBACK_MODPROBE);
    }

    #[test]
    fn read_modprobe_state_uses_file_when_present() {
        let path = tmp_path("kmodguard-state");
        fs::write(&path, "/usr/bin/modprobe\n").expect("write state");
        let snap = read_modprobe_state(&path);
        assert_eq!(snap, "/usr/bin/modprobe");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn require_root_matches_current_uid() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let result = require_root(&a);
        let uid = rustix::process::getuid().as_raw();
        if uid == 0 {
            assert!(result.is_ok(), "root peer must be accepted");
        } else {
            let err = result.expect_err("non-root peer must be rejected");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("unauthorized"),
                "expected unauthorized message, got: {msg}"
            );
        }
    }
}
