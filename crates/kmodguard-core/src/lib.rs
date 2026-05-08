use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_POLICY_PATH: &str = "/etc/kmodguard/policy.toml";
pub const DEFAULT_ORIGINAL_MODPROBE_PATH: &str = "/run/kmodguard/original_modprobe";
pub const DEFAULT_DAEMON_SOCKET_PATH: &str = "/run/kmodguard/daemon.sock";
pub const DEFAULT_HANDLER_PATH: &str = "/usr/libexec/kmodguard/kmodguard-hook";
pub const FALLBACK_MODPROBE: &str = "/usr/bin/modprobe";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Enforce,
    Audit,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AllowList {
    #[serde(default)]
    pub modules: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DenyList {
    #[serde(default)]
    pub modules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub version: u32,
    pub generated_at: DateTime<Utc>,
    pub kernel_release: String,
    pub mode: PolicyMode,
    #[serde(default)]
    pub allow: AllowList,
    #[serde(default)]
    pub deny: DenyList,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub token: String,
    pub resolved_modules: Vec<String>,
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub mode: PolicyMode,
    allow_modules: HashSet<String>,
    allow_aliases: HashSet<String>,
    deny_modules: HashSet<String>,
}

#[derive(Debug, Clone)]
struct AliasRule {
    regex: Regex,
    module: String,
}

#[derive(Debug, Clone, Default)]
pub struct ModuleResolver {
    canonical_modules: BTreeSet<String>,
    alias_rules: Vec<AliasRule>,
    aliases_by_module: HashMap<String, BTreeSet<String>>,
    resolve_cache: RefCell<HashMap<String, Vec<String>>>,
    resolve_cache_order: RefCell<VecDeque<String>>,
    resolve_cache_capacity: usize,
}

#[derive(Debug, Error)]
pub enum KmodguardError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml decode error: {0}")]
    TomlDecode(#[from] toml::de::Error),
    #[error("toml encode error: {0}")]
    TomlEncode(#[from] toml::ser::Error),
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
}

impl ModuleResolver {
    pub fn new(kernel_release: &str) -> Result<Self, KmodguardError> {
        let canonical_modules = read_proc_modules()?;
        let mut resolver = ModuleResolver {
            canonical_modules,
            alias_rules: Vec::new(),
            aliases_by_module: HashMap::new(),
            resolve_cache: RefCell::new(HashMap::new()),
            resolve_cache_order: RefCell::new(VecDeque::new()),
            resolve_cache_capacity: 2048,
        };
        resolver.load_alias_rules(kernel_release)?;
        Ok(resolver)
    }

    pub fn from_parts(
        modules: impl IntoIterator<Item = String>,
        alias_pairs: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, KmodguardError> {
        let canonical_modules = modules.into_iter().collect::<BTreeSet<_>>();
        let mut alias_rules = Vec::new();
        let mut aliases_by_module: HashMap<String, BTreeSet<String>> = HashMap::new();

        for (pattern, module) in alias_pairs {
            let regex = compile_alias(&pattern)?;
            aliases_by_module
                .entry(module.clone())
                .or_default()
                .insert(pattern.clone());
            alias_rules.push(AliasRule { regex, module });
        }

        Ok(Self {
            canonical_modules,
            alias_rules,
            aliases_by_module,
            resolve_cache: RefCell::new(HashMap::new()),
            resolve_cache_order: RefCell::new(VecDeque::new()),
            resolve_cache_capacity: 2048,
        })
    }

    pub fn loaded_modules(&self) -> Vec<String> {
        self.canonical_modules.iter().cloned().collect()
    }

    pub fn aliases_for(&self, module: &str) -> Vec<String> {
        self.aliases_by_module
            .get(module)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn resolve(&self, token: &str) -> Vec<String> {
        if let Some(cached) = self.resolve_cache.borrow().get(token) {
            return cached.clone();
        }

        let mut resolved = BTreeSet::new();

        if self.canonical_modules.contains(token) {
            resolved.insert(token.to_string());
        }

        for rule in &self.alias_rules {
            if rule.regex.is_match(token) {
                resolved.insert(rule.module.clone());
            }
        }

        if resolved.is_empty() {
            if let Ok(output) = Command::new(FALLBACK_MODPROBE)
                .arg("--resolve-alias")
                .arg(token)
                .output()
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines().map(str::trim).filter(|v| !v.is_empty()) {
                        resolved.insert(line.to_string());
                    }
                }
            }
        }

        let resolved_vec = resolved.into_iter().collect::<Vec<_>>();
        self.put_cache(token, &resolved_vec);
        resolved_vec
    }

    fn put_cache(&self, token: &str, resolved: &[String]) {
        if self.resolve_cache.borrow().contains_key(token) {
            return;
        }

        {
            let mut cache = self.resolve_cache.borrow_mut();
            cache.insert(token.to_string(), resolved.to_vec());
        }
        {
            let mut order = self.resolve_cache_order.borrow_mut();
            order.push_back(token.to_string());
            if order.len() > self.resolve_cache_capacity {
                if let Some(oldest) = order.pop_front() {
                    self.resolve_cache.borrow_mut().remove(&oldest);
                }
            }
        }
    }

    #[cfg(test)]
    fn cache_size(&self) -> usize {
        self.resolve_cache.borrow().len()
    }

    fn load_alias_rules(&mut self, kernel_release: &str) -> Result<(), KmodguardError> {
        let alias_file = PathBuf::from(format!("/lib/modules/{kernel_release}/modules.alias"));
        if !alias_file.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(alias_file)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() != 3 || parts[0] != "alias" {
                continue;
            }

            let pattern = parts[1].to_string();
            let module = parts[2].to_string();
            let regex = compile_alias(&pattern)?;
            self.aliases_by_module
                .entry(module.clone())
                .or_default()
                .insert(pattern.clone());
            self.alias_rules.push(AliasRule { regex, module });
        }

        Ok(())
    }
}

impl CompiledPolicy {
    pub fn from_policy(policy: &Policy) -> Self {
        Self {
            mode: policy.mode.clone(),
            allow_modules: policy.allow.modules.iter().cloned().collect(),
            allow_aliases: policy.allow.aliases.iter().cloned().collect(),
            deny_modules: policy.deny.modules.iter().cloned().collect(),
        }
    }
}

fn read_proc_modules() -> Result<BTreeSet<String>, KmodguardError> {
    let content = fs::read_to_string("/proc/modules")?;
    let modules = content
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    Ok(modules)
}

pub fn compile_alias(pattern: &str) -> Result<Regex, KmodguardError> {
    let escaped = regex::escape(pattern)
        .replace("\\*", ".*")
        .replace("\\?", ".");
    Ok(Regex::new(&format!("^{escaped}$"))?)
}

pub fn baseline_policy(kernel_release: &str) -> Result<Policy, KmodguardError> {
    let resolver = ModuleResolver::new(kernel_release)?;
    let modules = resolver.loaded_modules();
    let mut aliases = BTreeSet::new();

    for module in &modules {
        for alias in resolver.aliases_for(module) {
            aliases.insert(alias);
        }
    }

    Ok(Policy {
        version: 1,
        generated_at: Utc::now(),
        kernel_release: kernel_release.to_string(),
        mode: PolicyMode::Enforce,
        allow: AllowList {
            modules,
            aliases: aliases.into_iter().collect(),
        },
        deny: DenyList::default(),
    })
}

pub fn save_policy(path: &Path, policy: &Policy) -> Result<(), KmodguardError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(policy)?;
    fs::write(path, content)?;
    Ok(())
}

pub fn save_policy_atomic(path: &Path, policy: &Policy) -> Result<(), KmodguardError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&parent)?;

    let content = toml::to_string_pretty(policy)?;
    let tmp = unique_tmp_path(path);

    let write_result = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(KmodguardError::Io(err));
    }

    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(KmodguardError::Io(err));
    }

    if let Ok(dir) = fs::File::open(&parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

fn unique_tmp_path(target: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let stem = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "policy".to_string());
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    parent.join(format!(".{stem}.tmp.{pid}.{nanos}"))
}

pub fn allow_module(policy: &mut Policy, module: &str) -> bool {
    if policy.allow.modules.iter().any(|m| m == module) {
        return false;
    }
    policy.allow.modules.push(module.to_string());
    policy.allow.modules.sort_unstable();
    true
}

pub fn remove_module(policy: &mut Policy, module: &str) -> bool {
    let old_len = policy.allow.modules.len();
    policy.allow.modules.retain(|m| m != module);
    if policy.allow.modules.len() != old_len {
        policy.allow.modules.sort_unstable();
        true
    } else {
        false
    }
}

pub fn decide(policy: &CompiledPolicy, resolver: &ModuleResolver, token: &str) -> Decision {
    let resolved_modules = resolver.resolve(token);
    let audit = matches!(policy.mode, PolicyMode::Audit);
    let mk = |allowed: bool, reason: &str| Decision {
        token: token.to_string(),
        resolved_modules: resolved_modules.clone(),
        allowed,
        reason: reason.to_string(),
    };

    if policy.deny_modules.contains(token) {
        return mk(false, "explicitly denied");
    }
    if policy.allow_aliases.contains(token) {
        return mk(true, "alias allowed");
    }
    if resolved_modules.is_empty() {
        return if audit {
            mk(true, "audit: unresolved allowed")
        } else {
            mk(false, "unresolved token")
        };
    }
    if resolved_modules
        .iter()
        .any(|m| policy.allow_modules.contains(m))
    {
        return mk(true, "resolved allowed");
    }
    if audit {
        mk(true, "audit: would deny")
    } else {
        mk(false, "not in allowlist")
    }
}

pub fn kernel_release() -> Result<String, KmodguardError> {
    let output = Command::new("uname").arg("-r").output()?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_alias_matches() {
        let regex = compile_alias("pci:v*d*sv*sd*bc*sc*i*").expect("regex");
        assert!(regex.is_match("pci:v00008086d000015B8sv0000103Csd000089ABbc02sc00i00"));
    }

    #[test]
    fn decision_allows_by_alias_resolution() {
        let resolver = ModuleResolver::from_parts(
            vec!["e1000e".to_string()],
            vec![("pci:v*d*sv*sd*bc*sc*i*".to_string(), "e1000e".to_string())],
        )
        .expect("resolver");

        let policy = Policy {
            version: 1,
            generated_at: Utc::now(),
            kernel_release: "test".to_string(),
            mode: PolicyMode::Enforce,
            allow: AllowList {
                modules: vec!["e1000e".to_string()],
                aliases: vec![],
            },
            deny: DenyList::default(),
        };

        let compiled = CompiledPolicy::from_policy(&policy);
        let decision = decide(
            &compiled,
            &resolver,
            "pci:v00008086d000015B8sv0000103Csd000089ABbc02sc00i00",
        );
        assert!(decision.allowed);
    }

    #[test]
    fn deny_overrides_allow() {
        let resolver =
            ModuleResolver::from_parts(vec!["loop".to_string()], vec![]).expect("resolver");
        let policy = Policy {
            version: 1,
            generated_at: Utc::now(),
            kernel_release: "test".to_string(),
            mode: PolicyMode::Enforce,
            allow: AllowList {
                modules: vec!["loop".to_string()],
                aliases: vec![],
            },
            deny: DenyList {
                modules: vec!["loop".to_string()],
            },
        };
        let compiled = CompiledPolicy::from_policy(&policy);
        let decision = decide(&compiled, &resolver, "loop");
        assert!(!decision.allowed);
    }

    #[test]
    fn resolver_caches_repeated_resolution() {
        let resolver = ModuleResolver::from_parts(
            vec!["e1000e".to_string()],
            vec![("pci:v*d*sv*sd*bc*sc*i*".to_string(), "e1000e".to_string())],
        )
        .expect("resolver");
        let token = "pci:v00008086d000015B8sv0000103Csd000089ABbc02sc00i00";
        assert_eq!(resolver.cache_size(), 0);
        let first = resolver.resolve(token);
        assert_eq!(resolver.cache_size(), 1);
        let second = resolver.resolve(token);
        assert_eq!(resolver.cache_size(), 1);
        assert_eq!(first, second);
    }

    #[test]
    fn resolver_cache_is_bounded() {
        let module = "loop".to_string();
        let alias_pairs = (0..2500)
            .map(|i| (format!("token{i}"), module.clone()))
            .collect::<Vec<_>>();
        let resolver = ModuleResolver::from_parts(vec![module], alias_pairs).expect("resolver");

        for i in 0..2500 {
            let _ = resolver.resolve(&format!("token{i}"));
        }

        assert!(resolver.cache_size() <= 2048);
    }

    fn sample_policy() -> Policy {
        Policy {
            version: 1,
            generated_at: Utc::now(),
            kernel_release: "test".to_string(),
            mode: PolicyMode::Enforce,
            allow: AllowList {
                modules: vec!["loop".to_string()],
                aliases: vec![],
            },
            deny: DenyList::default(),
        }
    }

    fn unique_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = PathBuf::from(format!("/tmp/kmodguard-test-{name}-{nanos}"));
        fs::create_dir_all(&dir).expect("mkdir tmp");
        dir
    }

    #[test]
    fn save_policy_atomic_writes_with_0600_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("atomic-mode");
        let path = dir.join("policy.toml");
        save_policy_atomic(&path, &sample_policy()).expect("save");
        let mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_policy_atomic_cleans_up_temp_on_failure() {
        let dir = unique_dir("atomic-cleanup");
        let target = dir.join("policy.toml");
        fs::create_dir(&target).expect("mkdir blocker");

        let result = save_policy_atomic(&target, &sample_policy());
        assert!(result.is_err(), "rename onto a directory should fail");

        let leftover_temps: Vec<_> = fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                name.starts_with(".policy.toml.tmp.")
            })
            .collect();
        assert!(
            leftover_temps.is_empty(),
            "temp files leaked: {leftover_temps:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_allow_remove_is_deterministic() {
        let mut policy = Policy {
            version: 1,
            generated_at: Utc::now(),
            kernel_release: "test".to_string(),
            mode: PolicyMode::Enforce,
            allow: AllowList {
                modules: vec!["zmod".to_string(), "amod".to_string()],
                aliases: vec![],
            },
            deny: DenyList::default(),
        };
        assert!(allow_module(&mut policy, "bmod"));
        assert!(!allow_module(&mut policy, "bmod"));
        assert!(remove_module(&mut policy, "zmod"));
        assert!(!remove_module(&mut policy, "missing"));
        assert_eq!(policy.allow.modules, vec!["amod", "bmod"]);
    }
}
