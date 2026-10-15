//! Whether Apple's on-device model can judge on this Mac, as the Apple
//! judgement helper answers its `check` (spec section 4.4).
//!
//! This half carries no process and no engine, so every build has it: the
//! engine state on the wire names Apple's availability whichever build reads
//! it. The engine itself, which spawns the helper, is `apple_engine`, built
//! only with the `apple` feature: the crates.io build has no Apple engine.

use std::fmt;

use serde_json::Value;

/// The file name of the Apple judgement helper, beside the daemon and the
/// in-bundle CLI in the bundle.
pub const HELPER_NAME: &str = "agentsweep-apple-judge";

/// The reason given when the helper is not where it belongs or could not be
/// started.
pub const HELPER_MISSING: &str = "helper_missing";

/// The reason given when the helper answered something that is not an answer
/// to `check`.
pub const HELPER_FAILED: &str = "helper_failed";

/// Whether Apple's on-device model can be used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppleAvailability {
    /// The model answers.
    Available {
        /// The identifier the Verdict cache keys on: the full macOS version
        /// and build number.
        model_version: String,
        /// The context the framework reports, in tokens, where it reports one.
        context_size: Option<u32>,
    },
    /// The model cannot be used, and why: a reason Apple's framework names
    /// (`device_not_eligible`, `apple_intelligence_not_enabled`,
    /// `model_not_ready`, `unknown`), or [`HELPER_MISSING`] or
    /// [`HELPER_FAILED`].
    Unavailable {
        /// The reason, as the helper or AgentSweep names it.
        reason: String,
    },
}

impl AppleAvailability {
    /// True when the model answers.
    pub fn is_available(&self) -> bool {
        matches!(self, AppleAvailability::Available { .. })
    }

    /// The reason the model cannot be used, absent when it can.
    pub fn reason(&self) -> Option<&str> {
        match self {
            AppleAvailability::Available { .. } => None,
            AppleAvailability::Unavailable { reason } => Some(reason),
        }
    }

    /// Reads the helper's answer to `check`: `available`, the `reason` when
    /// it is not, `context_size` where the framework says, and
    /// `model_version`. Anything else is [`HELPER_FAILED`].
    pub fn from_check(answer: &Value) -> AppleAvailability {
        let failed = || AppleAvailability::Unavailable {
            reason: HELPER_FAILED.to_string(),
        };
        match answer.get("available").and_then(Value::as_bool) {
            Some(true) => match answer.get("model_version").and_then(Value::as_str) {
                Some(version) if !version.is_empty() => AppleAvailability::Available {
                    model_version: version.to_string(),
                    context_size: answer
                        .get("context_size")
                        .and_then(Value::as_u64)
                        .and_then(|size| u32::try_from(size).ok()),
                },
                _ => failed(),
            },
            Some(false) => AppleAvailability::Unavailable {
                reason: answer
                    .get("reason")
                    .and_then(Value::as_str)
                    .filter(|reason| is_reason_word(reason))
                    .unwrap_or("unknown")
                    .to_string(),
            },
            None => failed(),
        }
    }
}

/// A reason is a short word of lowercase letters and underscores; anything
/// else the helper might say is not passed on.
pub fn is_reason_word(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= 64
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

impl fmt::Display for AppleAvailability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppleAvailability::Available { model_version, .. } => {
                write!(f, "Apple on-device is available (macOS {model_version})")
            }
            AppleAvailability::Unavailable { reason } => {
                write!(f, "Apple on-device is unavailable: {reason}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_check_answer_reads_as_availability() {
        assert_eq!(
            AppleAvailability::from_check(&json!({
                "available": true, "context_size": 4096, "model_version": "26.6.2 (25G83)"
            })),
            AppleAvailability::Available {
                model_version: "26.6.2 (25G83)".to_string(),
                context_size: Some(4096),
            }
        );
        let off = AppleAvailability::from_check(&json!({
            "available": false, "reason": "apple_intelligence_not_enabled",
            "model_version": "26.6.2 (25G83)"
        }));
        assert_eq!(off.reason(), Some("apple_intelligence_not_enabled"));
        assert!(!off.is_available());
    }

    #[test]
    fn an_answer_that_is_not_a_check_answer_is_a_failed_helper() {
        for answer in [
            json!({}),
            json!({"available": "yes"}),
            json!({"available": true}),
            json!({"error": "malformed_request"}),
        ] {
            assert_eq!(
                AppleAvailability::from_check(&answer).reason(),
                Some(HELPER_FAILED)
            );
        }
        let odd = AppleAvailability::from_check(&json!({
            "available": false, "reason": "Something <b>else</b>"
        }));
        assert_eq!(odd.reason(), Some("unknown"));
    }
}
