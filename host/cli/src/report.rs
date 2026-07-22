use std::fmt::Write as _;

use crate::args::Target;
use crate::protocol::Counts;
use crate::terminal::{self, Tone};

#[derive(Debug)]
pub struct TargetReport {
    pub target: Target,
    pub counts: Option<Counts>,
    pub outcome: &'static str,
    pub detail: Option<String>,
}

pub fn combined(reports: &[TargetReport]) -> String {
    render(reports, false)
}

pub fn combined_for_terminal(reports: &[TargetReport]) -> String {
    render(reports, terminal::stdout_has_color())
}

fn render(reports: &[TargetReport], color: bool) -> String {
    let mut text = String::from("aarch64-vmsa FVP test summary\n");
    let mut total = Counts {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    for target in Target::ALL {
        let target_reports: Vec<_> = reports
            .iter()
            .filter(|report| report.target == target)
            .collect();
        if target_reports.is_empty() {
            continue;
        }

        let mut counts = Counts {
            passed: 0,
            failed: 0,
            skipped: 0,
        };
        for report in &target_reports {
            if let Some(report_counts) = &report.counts {
                counts.passed = counts.passed.saturating_add(report_counts.passed);
                counts.failed = counts.failed.saturating_add(report_counts.failed);
                counts.skipped = counts.skipped.saturating_add(report_counts.skipped);
            }
        }
        total.passed = total.passed.saturating_add(counts.passed);
        total.failed = total.failed.saturating_add(counts.failed);
        total.skipped = total.skipped.saturating_add(counts.skipped);

        let worst = target_reports
            .iter()
            .copied()
            .max_by_key(|report| outcome_rank(report.outcome))
            .expect("a non-empty target report group has a worst outcome");
        // A per-run summary still carries its diagnostic detail. The combined
        // summary deliberately omits boot-specific details because isolated
        // boots are an implementation detail of one logical target run.
        let detail = (target_reports.len() == 1)
            .then(|| worst.detail.as_deref())
            .flatten();
        write_target(&mut text, color, target, worst.outcome, &counts, detail);
    }

    write_counts_line(&mut text, color, "total", &total);
    text
}

fn write_target(
    text: &mut String,
    color: bool,
    target: Target,
    outcome: &str,
    counts: &Counts,
    detail: Option<&str>,
) {
    let target = terminal::paint(color, Tone::Active, &format!("{:<14}", target.as_str()));
    let outcome = terminal::paint(
        color,
        outcome_tone(outcome),
        &format!("{outcome:<11}"),
    );
    let passed = terminal::paint(
        color,
        count_tone(counts.passed, Tone::Success),
        &counts.passed.to_string(),
    );
    let failed = terminal::paint(
        color,
        count_tone(counts.failed, Tone::Failure),
        &counts.failed.to_string(),
    );
    let skipped = terminal::paint(
        color,
        count_tone(counts.skipped, Tone::Skipped),
        &counts.skipped.to_string(),
    );
    write!(
        text,
        "{target} {outcome} passed={passed} failed={failed} skipped={skipped}"
    )
    .expect("formatting a report into String is infallible");
    if let Some(detail) = detail {
        write!(text, " {detail}").expect("formatting a report into String is infallible");
    }
    text.push('\n');
}

fn write_counts_line(text: &mut String, color: bool, label: &str, counts: &Counts) {
    let passed = terminal::paint(
        color,
        count_tone(counts.passed, Tone::Success),
        &counts.passed.to_string(),
    );
    let failed = terminal::paint(
        color,
        count_tone(counts.failed, Tone::Failure),
        &counts.failed.to_string(),
    );
    let skipped = terminal::paint(
        color,
        count_tone(counts.skipped, Tone::Skipped),
        &counts.skipped.to_string(),
    );
    writeln!(
        text,
        "{label:<14} passed={passed} failed={failed} skipped={skipped}"
    )
    .expect("formatting a report into String is infallible");
}

fn outcome_rank(outcome: &str) -> u8 {
    match outcome {
        "passed" => 0,
        "unsupported" => 1,
        "failed" => 2,
        "invalid" => 3,
        "timeout" => 4,
        "malformed" | "harness-error" => 5,
        "startup-error" => 6,
        "build-error" => 7,
        "cancelled" => 8,
        _ => 9,
    }
}

fn outcome_tone(outcome: &str) -> Tone {
    match outcome {
        "passed" => Tone::Success,
        "unsupported" => Tone::Skipped,
        _ => Tone::Failure,
    }
}

fn count_tone(count: u32, nonzero: Tone) -> Tone {
    if count == 0 { Tone::Muted } else { nonzero }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(
        target: Target,
        outcome: &'static str,
        passed: u32,
        failed: u32,
        skipped: u32,
    ) -> TargetReport {
        TargetReport {
            target,
            counts: Some(Counts {
                passed,
                failed,
                skipped,
            }),
            outcome,
            detail: None,
        }
    }

    #[test]
    fn combines_isolated_boots_into_one_target_row() {
        let text = combined(&[
            report(Target::SecureEl2, "passed", 63, 0, 0),
            report(Target::SecureEl2, "passed", 1, 0, 0),
            report(Target::SecureEl2, "failed", 0, 1, 0),
            report(Target::SecureEl2, "timeout", 0, 1, 0),
        ]);

        assert_eq!(text.matches("secure-el2").count(), 1);
        assert!(text.contains(
            "secure-el2     timeout     passed=64 failed=2 skipped=0"
        ));
        assert!(text.contains("total          passed=64 failed=2 skipped=0"));
    }

    #[test]
    fn groups_countless_build_failures_without_duplicate_rows() {
        let text = combined(&[
            TargetReport {
                target: Target::RootEl3,
                counts: None,
                outcome: "build-error",
                detail: Some("first build failed".into()),
            },
            TargetReport {
                target: Target::RootEl3,
                counts: None,
                outcome: "build-error",
                detail: Some("second build failed".into()),
            },
        ]);

        assert_eq!(text.matches("root-el3").count(), 1);
        assert!(text.contains(
            "root-el3       build-error passed=0 failed=0 skipped=0"
        ));
        assert!(!text.contains("first build failed"));
        assert!(!text.contains("second build failed"));
    }

    #[test]
    fn preserves_detail_in_a_single_run_summary() {
        let text = combined(&[TargetReport {
            target: Target::RootEl3,
            counts: None,
            outcome: "build-error",
            detail: Some("firmware build failed".into()),
        }]);

        assert!(text.contains(
            "root-el3       build-error passed=0 failed=0 skipped=0 firmware build failed"
        ));
    }
}
