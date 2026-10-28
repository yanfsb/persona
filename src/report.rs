use serde::Serialize;

pub const REPORT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Pass,
    Fail,
    Unknown,
    Warn,
}

impl Status {
    fn rank(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Warn => 1,
            Self::Unknown => 2,
            Self::Fail => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub property: String,
    pub status: Status,
    pub expected: Option<String>,
    pub observed: Option<String>,
    pub coverage_reason: String,
}

impl Finding {
    pub fn pass(
        property: impl Into<String>,
        expected: impl Into<String>,
        observed: impl Into<String>,
        coverage_reason: impl Into<String>,
    ) -> Self {
        Self {
            property: property.into(),
            status: Status::Pass,
            expected: Some(expected.into()),
            observed: Some(observed.into()),
            coverage_reason: coverage_reason.into(),
        }
    }

    pub fn status(
        property: impl Into<String>,
        status: Status,
        expected: Option<String>,
        observed: Option<String>,
        coverage_reason: impl Into<String>,
    ) -> Self {
        Self {
            property: property.into(),
            status,
            expected,
            observed,
            coverage_reason: coverage_reason.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub version: u32,
    pub status: Status,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(mut findings: Vec<Finding>) -> Self {
        findings.sort_by(|left, right| left.property.cmp(&right.property));
        let status = findings
            .iter()
            .map(|finding| finding.status)
            .max_by_key(|status| status.rank())
            .unwrap_or(Status::Unknown);
        Self {
            version: REPORT_VERSION,
            status,
            findings,
        }
    }
}

pub fn exit_code(status: Status) -> u8 {
    match status {
        Status::Pass => 0,
        Status::Fail => 1,
        Status::Unknown => 3,
        Status::Warn => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::{Finding, Report, Status};

    #[test]
    fn aggregation_is_deterministic_and_uses_highest_severity() {
        let report = Report::new(vec![
            Finding::status("z", Status::Warn, None, None, "limited"),
            Finding::status("a", Status::Pass, None, None, "checked"),
            Finding::status("m", Status::Fail, None, None, "mismatch"),
        ]);

        assert_eq!(report.status, Status::Fail);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.property.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "m", "z"]
        );
    }
}
