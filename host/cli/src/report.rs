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
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut skipped = 0u32;
    for report in reports {
        if let Some(counts) = &report.counts {
            passed = passed.saturating_add(counts.passed);
            failed = failed.saturating_add(counts.failed);
            skipped = skipped.saturating_add(counts.skipped);
            let target = terminal::paint(
                color,
                Tone::Active,
                &format!("{:<14}", report.target.as_str()),
            );
            let outcome = terminal::paint(
                color,
                outcome_tone(report.outcome),
                &format!("{:<11}", report.outcome),
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
            writeln!(
                text,
                "{target} {outcome} passed={passed} failed={failed} skipped={skipped}"
            )
            .expect("formatting a report into String is infallible");
        } else {
            let target = terminal::paint(
                color,
                Tone::Active,
                &format!("{:<14}", report.target.as_str()),
            );
            let outcome = terminal::paint(
                color,
                outcome_tone(report.outcome),
                &format!("{:<11}", report.outcome),
            );
            writeln!(
                text,
                "{target} {outcome} {}",
                report
                    .detail
                    .as_deref()
                    .map_or("no details", |detail| detail)
            )
            .expect("formatting a report into String is infallible");
        }
    }
    let passed = terminal::paint(
        color,
        count_tone(passed, Tone::Success),
        &passed.to_string(),
    );
    let failed = terminal::paint(
        color,
        count_tone(failed, Tone::Failure),
        &failed.to_string(),
    );
    let skipped = terminal::paint(
        color,
        count_tone(skipped, Tone::Skipped),
        &skipped.to_string(),
    );
    writeln!(
        text,
        "total          passed={passed} failed={failed} skipped={skipped}"
    )
    .expect("formatting a report into String is infallible");
    text
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
