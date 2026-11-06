use crate::report::{Finding, Status};
use serde::Serialize;

pub const DECISION_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Status,
    GitPush,
    GitTagVerification,
    Run,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Allow,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Blocker {
    pub property: String,
    pub observed: Option<Status>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationDecision {
    pub version: u32,
    pub operation: Operation,
    pub verdict: Verdict,
    pub required: Vec<String>,
    pub blockers: Vec<Blocker>,
    pub findings: Vec<Finding>,
}

impl OperationDecision {
    pub fn is_allowed(&self) -> bool {
        self.verdict == Verdict::Allow
    }
}

/// Authorize an operation only when every declared required property has one
/// unambiguous PASS finding. Diagnostic findings outside `required` do not
/// affect authorization, and an empty requirement set is never permissive.
pub fn authorize(
    operation: Operation,
    mut required: Vec<String>,
    findings: Vec<Finding>,
) -> OperationDecision {
    required.sort();
    required.dedup();

    let mut blockers = Vec::new();
    if operation == Operation::Status {
        blockers.push(Blocker {
            property: "operation".to_owned(),
            observed: None,
            reason: "status is diagnostic and cannot authorize an operation".to_owned(),
        });
    } else if required.is_empty() {
        blockers.push(Blocker {
            property: "requirements".to_owned(),
            observed: None,
            reason: "no operation-specific authorization requirements were declared".to_owned(),
        });
    } else {
        for property in &required {
            let mut matching = findings
                .iter()
                .filter(|finding| finding.property == *property);
            match (matching.next(), matching.next()) {
                (None, _) => blockers.push(Blocker {
                    property: property.clone(),
                    observed: None,
                    reason: "required property evidence is missing".to_owned(),
                }),
                (Some(_), Some(_)) => blockers.push(Blocker {
                    property: property.clone(),
                    observed: None,
                    reason: "duplicate findings make required property evidence ambiguous"
                        .to_owned(),
                }),
                (Some(finding), None) if finding.status == Status::Pass => {}
                (Some(finding), None) => blockers.push(Blocker {
                    property: property.clone(),
                    observed: Some(finding.status),
                    reason: format!("required property is not PASS: {}", finding.coverage_reason),
                }),
            }
        }
    }

    let verdict = if blockers.is_empty() {
        Verdict::Allow
    } else {
        Verdict::Block
    };
    OperationDecision {
        version: DECISION_VERSION,
        operation,
        verdict,
        required,
        blockers,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::{Operation, Verdict, authorize};
    use crate::report::{Finding, Status};

    fn pass(property: &str) -> Finding {
        Finding::pass(property, "expected", "observed", "fixture evidence")
    }

    fn status(property: &str, status: Status) -> Finding {
        Finding::status(property, status, None, None, "fixture evidence")
    }

    #[test]
    fn unrelated_unknown_does_not_veto_complete_required_evidence() {
        let decision = authorize(
            Operation::GitPush,
            vec!["destination".to_owned(), "identity".to_owned()],
            vec![
                status("informational.auth", Status::Unknown),
                pass("identity"),
                pass("destination"),
            ],
        );
        assert_eq!(decision.verdict, Verdict::Allow);
        assert!(decision.blockers.is_empty());
    }

    #[test]
    fn required_unknown_fail_warn_and_missing_evidence_block() {
        for (property, evidence) in [
            ("unknown", Some(status("unknown", Status::Unknown))),
            ("fail", Some(status("fail", Status::Fail))),
            ("warn", Some(status("warn", Status::Warn))),
            ("missing", None),
        ] {
            let findings = evidence.into_iter().collect();
            let decision = authorize(Operation::GitPush, vec![property.to_owned()], findings);
            assert_eq!(decision.verdict, Verdict::Block, "{property}");
            assert_eq!(decision.blockers[0].property, property);
        }
    }

    #[test]
    fn empty_requirements_and_duplicate_findings_never_authorize() {
        assert_eq!(
            authorize(Operation::GitPush, Vec::new(), vec![pass("anything")]).verdict,
            Verdict::Block
        );
        assert_eq!(
            authorize(
                Operation::GitPush,
                vec!["identity".to_owned()],
                vec![pass("identity"), pass("identity")],
            )
            .verdict,
            Verdict::Block
        );
    }

    #[test]
    fn diagnostic_status_is_never_an_authorizing_operation() {
        assert_eq!(
            authorize(
                Operation::Status,
                vec!["identity".to_owned()],
                vec![pass("identity")]
            )
            .verdict,
            Verdict::Block
        );
    }

    #[test]
    fn decision_json_is_versioned_and_keeps_diagnostic_unknowns_visible() {
        let decision = authorize(
            Operation::GitPush,
            vec!["destination".to_owned()],
            vec![pass("destination"), status("ssh", Status::Unknown)],
        );
        let json = serde_json::to_value(decision).expect("serialize operation decision");
        assert_eq!(json["version"], 2);
        assert_eq!(json["operation"], "git_push");
        assert_eq!(json["verdict"], "ALLOW");
        assert_eq!(json["findings"][1]["status"], "UNKNOWN");
    }
}
