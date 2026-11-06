use crate::git::{GitClient, PushTuple};
use std::collections::HashSet;
use std::path::Path;

const MAX_UPDATES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateClass {
    UnchangedBranch,
    InitialBranch,
    ExistingBranch,
    FastForwardBranch,
    RewriteBranch,
    DeleteBranch,
    TagUpdate,
    AnnotatedTag,
    LightweightTag,
    DeleteTag,
    UnsupportedRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    Empty,
    TooManyUpdates,
    InvalidOid,
    InvalidRef,
    DuplicateRemoteRef,
    UnsupportedRefKind,
    HistoryUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedUpdate {
    local_ref: String,
    local_oid: String,
    remote_ref: String,
    expected_remote_oid: String,
    expected_lease_oid: Option<String>,
    class: UpdateClass,
}

impl PlannedUpdate {
    pub fn local_ref(&self) -> &str {
        &self.local_ref
    }

    pub fn local_oid(&self) -> &str {
        &self.local_oid
    }

    pub fn remote_ref(&self) -> &str {
        &self.remote_ref
    }

    pub fn expected_remote_oid(&self) -> &str {
        &self.expected_remote_oid
    }

    pub fn expected_lease_oid(&self) -> Option<&str> {
        self.expected_lease_oid.as_deref()
    }

    pub fn class(&self) -> UpdateClass {
        self.class
    }

    pub fn matches_native_update(&self, tuple: &PushTuple) -> bool {
        self.local_ref == tuple.local_ref
            && self.local_oid == tuple.local_oid
            && self.remote_ref == tuple.remote_ref
            && self.expected_remote_oid == tuple.remote_oid
            && self
                .expected_lease_oid
                .as_ref()
                .is_none_or(|lease_oid| lease_oid == &tuple.remote_oid)
    }
}

/// An immutable snapshot of the exact updates requested at the authorization boundary.
/// Git may negotiate different remote OIDs later; those are rejected by the second barrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationPlan {
    remote: String,
    destination: String,
    updates: Vec<PlannedUpdate>,
}

impl PublicationPlan {
    pub fn new(
        remote: impl Into<String>,
        destination: impl Into<String>,
        tuples: &[PushTuple],
    ) -> Result<Self, PlanError> {
        if tuples.is_empty() {
            return Err(PlanError::Empty);
        }
        if tuples.len() > MAX_UPDATES {
            return Err(PlanError::TooManyUpdates);
        }
        let mut remote_refs = HashSet::new();
        let mut updates = Vec::with_capacity(tuples.len());
        for tuple in tuples {
            let class = classify(tuple)?;
            if !remote_refs.insert(tuple.remote_ref.as_str()) {
                return Err(PlanError::DuplicateRemoteRef);
            }
            updates.push(PlannedUpdate {
                local_ref: tuple.local_ref.clone(),
                local_oid: tuple.local_oid.clone(),
                remote_ref: tuple.remote_ref.clone(),
                expected_remote_oid: tuple.remote_oid.clone(),
                expected_lease_oid: None,
                class,
            });
        }
        Ok(Self {
            remote: remote.into(),
            destination: destination.into(),
            updates,
        })
    }

    pub fn remote(&self) -> &str {
        &self.remote
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }

    pub fn updates(&self) -> &[PlannedUpdate] {
        &self.updates
    }

    /// Return a new snapshot with local graph/object kinds classified. The original plan is unchanged.
    pub fn with_expected_lease(
        mut self,
        remote_ref: &str,
        expected_oid: &str,
    ) -> Result<Self, PlanError> {
        if !valid_oid(expected_oid) {
            return Err(PlanError::InvalidOid);
        }
        let update = self
            .updates
            .iter_mut()
            .find(|update| update.remote_ref == remote_ref)
            .ok_or(PlanError::InvalidRef)?;
        if !matches!(
            update.class,
            UpdateClass::ExistingBranch
                | UpdateClass::DeleteBranch
                | UpdateClass::DeleteTag
                | UpdateClass::TagUpdate
        ) {
            return Err(PlanError::UnsupportedRefKind);
        }
        update.expected_lease_oid = Some(expected_oid.to_owned());
        Ok(self)
    }

    pub fn with_local_history(
        mut self,
        git: &GitClient,
        root: &Path,
        deadline: std::time::Instant,
    ) -> Result<Self, PlanError> {
        for update in &mut self.updates {
            if std::time::Instant::now() >= deadline {
                return Err(PlanError::HistoryUnavailable);
            }
            match update.class {
                UpdateClass::ExistingBranch => {
                    update.class =
                        match git.is_ancestor(root, &update.expected_remote_oid, &update.local_oid)
                        {
                            Ok(true) => UpdateClass::FastForwardBranch,
                            Ok(false) => UpdateClass::RewriteBranch,
                            Err(_) => return Err(PlanError::HistoryUnavailable),
                        };
                }
                UpdateClass::TagUpdate => {
                    update.class = match git.object_type(root, &update.local_oid) {
                        Ok(kind) if kind == "commit" => UpdateClass::LightweightTag,
                        Ok(kind) if kind == "tag" => {
                            let mut oid = update.local_oid.clone();
                            let mut visited = HashSet::new();
                            let mut depth = 0;
                            loop {
                                if depth == 32 || !visited.insert(oid.clone()) {
                                    return Err(PlanError::HistoryUnavailable);
                                }
                                let (target_oid, target_kind) = git
                                    .tag_target(root, &oid)
                                    .map_err(|_| PlanError::HistoryUnavailable)?;
                                match target_kind.as_str() {
                                    "commit"
                                        if git
                                            .object_type(root, &target_oid)
                                            .is_ok_and(|kind| kind == "commit") =>
                                    {
                                        break UpdateClass::AnnotatedTag;
                                    }
                                    "tag"
                                        if git
                                            .object_type(root, &target_oid)
                                            .is_ok_and(|kind| kind == "tag") =>
                                    {
                                        oid = target_oid;
                                        depth += 1;
                                    }
                                    _ => break UpdateClass::UnsupportedRef,
                                }
                            }
                        }
                        Ok(_) => UpdateClass::UnsupportedRef,
                        Err(_) => return Err(PlanError::HistoryUnavailable),
                    };
                }
                _ => {}
            }
        }
        Ok(self)
    }
}

fn classify(tuple: &PushTuple) -> Result<UpdateClass, PlanError> {
    if !valid_oid(&tuple.local_oid)
        || !valid_oid(&tuple.remote_oid)
        || tuple.local_oid.len() != tuple.remote_oid.len()
    {
        return Err(PlanError::InvalidOid);
    }
    let deleting = tuple.local_ref == "(delete)" || is_zero_oid(&tuple.local_oid);
    let local_branch = tuple.local_ref.starts_with("refs/heads/");
    let remote_branch = tuple.remote_ref.starts_with("refs/heads/");
    let local_tag = tuple.local_ref.starts_with("refs/tags/");
    let remote_tag = tuple.remote_ref.starts_with("refs/tags/");
    let remote_deleted = is_zero_oid(&tuple.remote_oid);
    if !valid_ref(&tuple.remote_ref) || (!deleting && !valid_ref(&tuple.local_ref)) {
        return Err(PlanError::InvalidRef);
    }
    if deleting && remote_branch {
        return Ok(UpdateClass::DeleteBranch);
    }
    if local_branch && remote_branch {
        return Ok(if deleting {
            UpdateClass::DeleteBranch
        } else if remote_deleted {
            UpdateClass::InitialBranch
        } else if tuple.local_oid == tuple.remote_oid {
            UpdateClass::UnchangedBranch
        } else {
            UpdateClass::ExistingBranch
        });
    }
    if (local_tag || deleting) && remote_tag {
        return Ok(if deleting {
            UpdateClass::DeleteTag
        } else {
            UpdateClass::TagUpdate
        });
    }
    if deleting {
        return Err(PlanError::UnsupportedRefKind);
    }
    Ok(UpdateClass::UnsupportedRef)
}

fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_zero_oid(oid: &str) -> bool {
    oid.bytes().all(|byte| byte == b'0')
}

fn valid_ref(refname: &str) -> bool {
    !refname.is_empty()
        && refname.starts_with("refs/")
        && !refname
            .bytes()
            .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(local_ref: &str, local_oid: &str, remote_ref: &str, remote_oid: &str) -> PushTuple {
        PushTuple {
            local_ref: local_ref.to_owned(),
            local_oid: local_oid.to_owned(),
            remote_ref: remote_ref.to_owned(),
            remote_oid: remote_oid.to_owned(),
        }
    }

    #[test]
    fn plan_freezes_requested_refs_and_oids() {
        let local = "a".repeat(40);
        let plan = PublicationPlan::new(
            "origin",
            "https://github.com/example/project.git",
            &[tuple(
                "refs/heads/main",
                &local,
                "refs/heads/main",
                &"0".repeat(40),
            )],
        )
        .unwrap();
        assert_eq!(plan.remote(), "origin");
        assert_eq!(plan.updates()[0].local_oid(), local);
        assert_eq!(plan.updates()[0].expected_remote_oid(), "0".repeat(40));
        assert_eq!(plan.updates()[0].class(), UpdateClass::InitialBranch);
    }

    #[test]
    fn force_lease_is_bound_to_the_exact_planned_remote_oid_and_tuple() {
        let update = tuple(
            "refs/heads/main",
            &"b".repeat(40),
            "refs/heads/main",
            &"a".repeat(40),
        );
        let plan = PublicationPlan::new("origin", "url", std::slice::from_ref(&update))
            .unwrap()
            .with_expected_lease("refs/heads/main", &"a".repeat(40))
            .unwrap();
        assert_eq!(
            plan.updates()[0].expected_lease_oid(),
            Some(&"a".repeat(40)[..])
        );
        assert!(plan.updates()[0].matches_native_update(&update));
        let changed = tuple(
            "refs/heads/main",
            &"b".repeat(40),
            "refs/heads/main",
            &"c".repeat(40),
        );
        assert!(!plan.updates()[0].matches_native_update(&changed));
    }

    #[test]
    fn deletion_plan_requires_the_exact_advertised_remote_object() {
        let remote_oid = "c".repeat(40);
        let update = tuple(
            "(delete)",
            &"0".repeat(40),
            "refs/heads/obsolete",
            &remote_oid,
        );
        let plan = PublicationPlan::new("origin", "url", std::slice::from_ref(&update)).unwrap();
        assert_eq!(plan.updates()[0].class(), UpdateClass::DeleteBranch);
        let leased = plan
            .with_expected_lease("refs/heads/obsolete", &remote_oid)
            .unwrap();
        assert!(leased.updates()[0].matches_native_update(&update));
        let changed = tuple(
            "(delete)",
            &"0".repeat(40),
            "refs/heads/obsolete",
            &"d".repeat(40),
        );
        assert!(!leased.updates()[0].matches_native_update(&changed));
    }

    #[test]
    fn planner_rejects_ambiguous_and_unbounded_updates() {
        let initial = tuple(
            "refs/heads/main",
            &"a".repeat(40),
            "refs/heads/main",
            &"0".repeat(40),
        );
        assert_eq!(
            PublicationPlan::new("origin", "url", &[]),
            Err(PlanError::Empty)
        );
        assert_eq!(
            PublicationPlan::new("origin", "url", &[initial.clone(), initial]),
            Err(PlanError::DuplicateRemoteRef)
        );
        let updates = (0..17)
            .map(|index| {
                tuple(
                    &format!("refs/heads/b{index}"),
                    &"a".repeat(40),
                    &format!("refs/heads/b{index}"),
                    &"0".repeat(40),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            PublicationPlan::new("origin", "url", &updates),
            Err(PlanError::TooManyUpdates)
        );
    }

    #[test]
    fn classifies_destructive_or_unverified_ref_kinds_without_authorizing_them() {
        let branch_delete = tuple(
            "(delete)",
            &"0".repeat(40),
            "refs/heads/main",
            &"a".repeat(40),
        );
        assert_eq!(classify(&branch_delete).unwrap(), UpdateClass::DeleteBranch);
        let tag = tuple(
            "refs/tags/v1",
            &"a".repeat(40),
            "refs/tags/v1",
            &"0".repeat(40),
        );
        assert_eq!(classify(&tag).unwrap(), UpdateClass::TagUpdate);
        let other = tuple(
            "refs/notes/commits",
            &"a".repeat(40),
            "refs/notes/commits",
            &"0".repeat(40),
        );
        assert_eq!(classify(&other).unwrap(), UpdateClass::UnsupportedRef);
    }
}
