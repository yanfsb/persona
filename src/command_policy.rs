use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CommandPolicyMode {
    /// Default deny: only commands matched by `allow` (and not `deny`) are permitted.
    Allowlist,
    /// Default allow: commands are permitted unless matched by `deny`.
    #[default]
    Denylist,
}

/// Per-profile allowlist and denylist for managed commands.
///
/// `deny` rules always take precedence over `allow` rules and over `Denylist`
/// mode. Identity-separation invariants (author/committer/signing injection,
/// credential binding, SSH isolation, and destination guardrails) still apply
/// even when a command is permitted.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<CommandPolicyMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandPolicyDenial {
    DeniedByRule(String),
    NotInAllowlist,
    InvalidSelector,
}

impl CommandPolicyDenial {
    pub fn describe(&self, kind: &str, selector: &str) -> String {
        match self {
            Self::DeniedByRule(rule) => {
                format!("{kind} operation `{selector}` is blocked by profile deny rule `{rule}`")
            }
            Self::NotInAllowlist => format!(
                "{kind} operation `{selector}` is not permitted by the selected profile's allowlist"
            ),
            Self::InvalidSelector => {
                format!("{kind} operation `{selector}` cannot be evaluated by command policy")
            }
        }
    }
}

impl CommandPolicy {
    pub fn is_default(&self) -> bool {
        self.mode.is_none() && self.allow.is_none() && self.deny.is_empty()
    }

    pub fn effective_mode(&self) -> CommandPolicyMode {
        self.mode.unwrap_or_else(|| {
            if self.allow.is_some() {
                CommandPolicyMode::Allowlist
            } else {
                CommandPolicyMode::Denylist
            }
        })
    }

    pub fn is_valid(&self) -> bool {
        let valid_list = |values: &[String]| {
            let mut seen = HashSet::new();
            values
                .iter()
                .all(|value| is_valid_rule(value) && seen.insert(value.as_str()))
        };
        self.allow.as_deref().is_none_or(valid_list) && valid_list(&self.deny)
    }

    /// Backwards-compatible single-selector check without invocation flags.
    pub fn permits(&self, selector: &str) -> bool {
        self.evaluate(&[selector], &[]).is_ok()
    }

    /// Evaluate an operation represented by one or more semantic selectors
    /// (for example `["push.force", "push.delete"]`) and raw CLI flags.
    pub fn evaluate(&self, selectors: &[&str], flags: &[&str]) -> Result<(), CommandPolicyDenial> {
        if selectors.is_empty()
            || selectors
                .iter()
                .any(|selector| !is_valid_runtime_selector(selector))
        {
            return Err(CommandPolicyDenial::InvalidSelector);
        }

        if let Some(rule) = self
            .deny
            .iter()
            .find(|rule| rule_matches_any(rule, selectors, flags))
        {
            return Err(CommandPolicyDenial::DeniedByRule(rule.clone()));
        }

        match self.effective_mode() {
            CommandPolicyMode::Denylist => Ok(()),
            CommandPolicyMode::Allowlist => {
                let allowed = self.allow.as_deref().unwrap_or(&[]);
                let all_permitted = selectors.iter().all(|selector| {
                    allowed
                        .iter()
                        .any(|rule| rule_matches_single(rule, selector, flags))
                });
                if all_permitted {
                    Ok(())
                } else {
                    Err(CommandPolicyDenial::NotInAllowlist)
                }
            }
        }
    }
}

fn rule_matches_any(rule: &str, selectors: &[&str], flags: &[&str]) -> bool {
    selectors
        .iter()
        .any(|selector| rule_matches_single(rule, selector, flags))
}

fn rule_matches_single(rule: &str, selector: &str, flags: &[&str]) -> bool {
    if let Some((selector_pattern, flag_pattern)) = rule.split_once(' ') {
        selector_matches_pattern(selector, selector_pattern)
            && flag_matches_pattern(flags, flag_pattern)
    } else {
        selector_matches_pattern(selector, rule)
    }
}

fn selector_matches_pattern(selector: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern == selector {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return selector == prefix
            || selector
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('.'));
    }
    selector
        .strip_prefix(pattern)
        .is_some_and(|rest| rest.starts_with('.'))
}

fn flag_matches_pattern(flags: &[&str], pattern: &str) -> bool {
    flags.iter().any(|flag| {
        *flag == pattern
            || flag
                .strip_prefix(pattern)
                .is_some_and(|rest| rest.starts_with('='))
    })
}

pub fn is_valid_runtime_selector(selector: &str) -> bool {
    !selector.is_empty()
        && !selector.starts_with('.')
        && !selector.ends_with('.')
        && !selector.contains("..")
        && !selector.contains('*')
        && selector.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
}

pub fn is_valid_rule(rule: &str) -> bool {
    if rule.is_empty() || rule.trim() != rule {
        return false;
    }
    let mut parts = rule.split(' ');
    let Some(selector_pattern) = parts.next() else {
        return false;
    };
    if !is_valid_selector_pattern(selector_pattern) {
        return false;
    }
    match (parts.next(), parts.next()) {
        (None, None) => true,
        (Some(flag_pattern), None) => is_valid_flag_pattern(flag_pattern),
        _ => false,
    }
}

fn is_valid_selector_pattern(pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let body = pattern.strip_suffix(".*").unwrap_or(pattern);
    !body.is_empty()
        && !body.starts_with('.')
        && !body.ends_with('.')
        && !body.contains("..")
        && !body.contains('*')
        && body.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
}

fn is_valid_flag_pattern(flag: &str) -> bool {
    flag.len() >= 2
        && flag.starts_with('-')
        && flag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'=' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denylist_mode_permits_everyday_commands_and_enforces_flag_and_wildcard_denies() {
        let policy = CommandPolicy {
            mode: Some(CommandPolicyMode::Denylist),
            allow: None,
            deny: vec![
                "submodule".to_owned(),
                "push --force".to_owned(),
                "auth.*".to_owned(),
            ],
        };
        assert!(policy.evaluate(&["status"], &[]).is_ok());
        assert!(policy.evaluate(&["stash"], &[]).is_ok());
        assert!(policy.evaluate(&["push"], &["--atomic"]).is_ok());
        assert!(matches!(
            policy.evaluate(&["push.force"], &["--force"]),
            Err(CommandPolicyDenial::DeniedByRule(ref rule)) if rule == "push --force"
        ));
        assert!(matches!(
            policy.evaluate(&["push"], &["--force=yes"]),
            Err(CommandPolicyDenial::DeniedByRule(ref rule)) if rule == "push --force"
        ));
        assert!(matches!(
            policy.evaluate(&["submodule"], &[]),
            Err(CommandPolicyDenial::DeniedByRule(ref rule)) if rule == "submodule"
        ));
        assert!(matches!(
            policy.evaluate(&["auth.switch"], &[]),
            Err(CommandPolicyDenial::DeniedByRule(ref rule)) if rule == "auth.*"
        ));
    }

    #[test]
    fn allowlist_mode_preserves_parent_child_semantics_and_deny_precedence() {
        let policy = CommandPolicy {
            mode: None,
            allow: Some(vec!["status".to_owned(), "fetch.all".to_owned()]),
            deny: vec!["push".to_owned()],
        };
        assert_eq!(policy.effective_mode(), CommandPolicyMode::Allowlist);
        assert!(policy.permits("status"));
        assert!(policy.permits("fetch.all"));
        assert!(!policy.permits("fetch"));
        assert!(!policy.permits("push"));

        let broad_allow = CommandPolicy {
            mode: None,
            allow: Some(vec!["fetch".to_owned()]),
            deny: vec!["fetch.all".to_owned()],
        };
        assert!(broad_allow.permits("fetch"));
        assert!(!broad_allow.permits("fetch.all"));

        let broad_deny = CommandPolicy {
            mode: None,
            allow: Some(vec!["fetch.all".to_owned()]),
            deny: vec!["fetch".to_owned()],
        };
        assert!(!broad_deny.permits("fetch.all"));
    }

    #[test]
    fn rejects_malformed_and_shell_like_rules() {
        for bad in [
            "",
            " status",
            "status;id",
            "*foo",
            "foo.*.bar",
            "push --force extra",
            "push not-a-flag",
            "STATUS",
        ] {
            assert!(!is_valid_rule(bad), "{bad:?}");
        }
        for good in [
            "*",
            "status",
            "fetch.all",
            "tag.*",
            "push --force",
            "commit --no-verify",
            "pr.view",
        ] {
            assert!(is_valid_rule(good), "{good:?}");
        }
    }
}
