use std::collections::BTreeSet;

use crate::settings::{PROTOCOL_LINE_LIMIT, PROTOCOL_VERSION, RESULT_PREFIX, TEST_NAME_LIMIT};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Counts {
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    Begin { target: String },
    Capability { name: String, value: u64 },
    Run { name: String },
    Pass { name: String },
    Fail { name: String, reason: String },
    Skip { name: String, reason: String },
    End(Counts),
}

#[derive(Debug)]
pub struct Parser {
    began: bool,
    ended: bool,
    active: Option<String>,
    completed: BTreeSet<String>,
    counts: Counts,
    target: Option<String>,
}

impl Parser {
    pub fn new() -> Self {
        Self {
            began: false,
            ended: false,
            active: None,
            completed: BTreeSet::new(),
            counts: Counts {
                passed: 0,
                failed: 0,
                skipped: 0,
            },
            target: None,
        }
    }

    pub fn parse_line(&mut self, line: &str) -> Result<Option<Event>, String> {
        if !line.starts_with(RESULT_PREFIX) {
            return Ok(None);
        }
        if line.len() > PROTOCOL_LINE_LIMIT {
            return Err(format!(
                "protocol line exceeds {PROTOCOL_LINE_LIMIT}-byte limit"
            ));
        }
        let Some(payload) = line.strip_prefix(RESULT_PREFIX) else {
            return Ok(None);
        };
        let payload = payload
            .strip_prefix(' ')
            .ok_or("missing space after protocol prefix")?;
        let mut words = payload.split_ascii_whitespace();
        let kind = words.next().ok_or("empty protocol record")?;
        if self.ended {
            return Err(format!("protocol record after END: {kind}"));
        }
        if !self.began && kind != "BEGIN" {
            return Err(format!("protocol record before BEGIN: {kind}"));
        }
        let event = match kind {
            "BEGIN" => {
                if self.began {
                    return Err("duplicate BEGIN".into());
                }
                let protocol = numeric_field(&mut words, "protocol")?;
                if protocol != PROTOCOL_VERSION {
                    return Err(format!(
                        "unsupported protocol version {protocol}; expected {PROTOCOL_VERSION}"
                    ));
                }
                let target = protocol_name(one_field(&mut words, "target")?, "target")?.to_owned();
                no_more(words)?;
                self.began = true;
                self.target = Some(target.clone());
                Event::Begin { target }
            }
            "CAP" => {
                ensure_idle(self)?;
                let field = words.next().ok_or("CAP requires one field")?;
                no_more(words)?;
                let (name, raw) = split_field(field)?;
                if name.is_empty() {
                    return Err("empty capability name".into());
                }
                protocol_name(name, "capability name")?;
                let value = raw.parse::<u64>().map_err(|_| "invalid capability value")?;
                Event::Capability {
                    name: name.into(),
                    value,
                }
            }
            "RUN" => {
                ensure_idle(self)?;
                let name = protocol_name(one_word(&mut words, "RUN test name")?, "RUN test name")?
                    .to_owned();
                no_more(words)?;
                if self.completed.contains(&name) {
                    return Err(format!("test run twice: {name}"));
                }
                self.active = Some(name.clone());
                Event::Run { name }
            }
            "PASS" => {
                let name = completion_name(self, &mut words)?;
                self.counts.passed = self
                    .counts
                    .passed
                    .checked_add(1)
                    .ok_or("pass counter overflow")?;
                Event::Pass { name }
            }
            "FAIL" => {
                let name = completion_name_first(self, &mut words)?;
                let reason = required_reason(words)?;
                finish_completion(self, &name)?;
                self.counts.failed = self
                    .counts
                    .failed
                    .checked_add(1)
                    .ok_or("fail counter overflow")?;
                Event::Fail { name, reason }
            }
            "SKIP" => {
                ensure_idle(self)?;
                let name =
                    protocol_name(one_word(&mut words, "SKIP test name")?, "SKIP test name")?
                        .to_owned();
                if self.completed.contains(&name) {
                    return Err(format!("duplicate test completion: {name}"));
                }
                let reason = required_reason(words)?;
                self.completed.insert(name.clone());
                self.counts.skipped = self
                    .counts
                    .skipped
                    .checked_add(1)
                    .ok_or("skip counter overflow")?;
                Event::Skip { name, reason }
            }
            "END" => {
                ensure_idle(self)?;
                let declared = Counts {
                    passed: numeric_field(&mut words, "passed")?,
                    failed: numeric_field(&mut words, "failed")?,
                    skipped: numeric_field(&mut words, "skipped")?,
                };
                no_more(words)?;
                if declared != self.counts {
                    return Err(format!(
                        "END counters {:?} do not match observed {:?}",
                        declared, self.counts
                    ));
                }
                self.ended = true;
                Event::End(declared)
            }
            unknown => return Err(format!("unknown protocol record: {unknown}")),
        };
        Ok(Some(event))
    }

    pub fn finish(&self) -> Result<Counts, String> {
        if !self.began {
            return Err("missing BEGIN".into());
        }
        if self.active.is_some() {
            return Err("result stream ended with an active test".into());
        }
        if !self.ended {
            return Err("missing END".into());
        }
        Ok(self.counts.clone())
    }

    pub fn has_begun(&self) -> bool {
        self.began
    }
    pub fn has_ended(&self) -> bool {
        self.ended
    }
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }
    pub fn active_test(&self) -> Option<&str> {
        self.active.as_deref()
    }
    pub fn observed_counts(&self) -> &Counts {
        &self.counts
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

pub fn validate_parser() -> Result<(), String> {
    let mut valid = Parser::new();
    for line in [
        "@@VMSA BEGIN protocol=1 target=self-check",
        "@@VMSA CAP rme=1",
        "@@VMSA RUN smoke.pass",
        "@@VMSA PASS smoke.pass",
        "@@VMSA SKIP smoke.skip reason=unsupported",
        "@@VMSA END passed=1 failed=0 skipped=1",
    ] {
        valid.parse_line(line)?;
    }
    valid.finish()?;

    for records in [
        &["@@VMSA PASS smoke.pass"][..],
        &[
            "@@VMSA BEGIN protocol=1 target=x",
            "@@VMSA BEGIN protocol=1 target=x",
        ][..],
        &["@@VMSA BEGIN protocol=1 target=x", "@@VMSA UNKNOWN value=1"][..],
        &["@@VMSA BEGIN protocol=1 target=x", "@@VMSA PASS smoke.pass"][..],
        &[
            "@@VMSA BEGIN protocol=1 target=x",
            "@@VMSA RUN smoke.pass",
            "@@VMSA PASS smoke.pass",
            "@@VMSA END passed=0 failed=0 skipped=0",
        ][..],
        &["@@VMSA BEGIN protocol=2 target=x"][..],
        &[
            "@@VMSA BEGIN protocol=1 target=x",
            "@@VMSA END passed=0 failed=0 skipped=0",
            "@@VMSA RUN smoke.late",
        ][..],
    ] {
        let mut parser = Parser::new();
        let rejected_while_parsing = records
            .iter()
            .any(|record| parser.parse_line(record).is_err());
        if !rejected_while_parsing && parser.finish().is_ok() {
            return Err("strict parser accepted a malformed self-check stream".into());
        }
    }
    let oversized = format!("@@VMSA RUN {}", "x".repeat(PROTOCOL_LINE_LIMIT));
    let mut parser = Parser::new();
    parser.parse_line("@@VMSA BEGIN protocol=1 target=x")?;
    if parser.parse_line(&oversized).is_ok() {
        return Err("strict parser accepted an oversized protocol line".into());
    }
    let long_name = format!("@@VMSA RUN {}", "x".repeat(TEST_NAME_LIMIT + 1));
    let mut parser = Parser::new();
    parser.parse_line("@@VMSA BEGIN protocol=1 target=x")?;
    if parser.parse_line(&long_name).is_ok() {
        return Err("strict parser accepted an oversized test name".into());
    }
    Ok(())
}

fn ensure_idle(parser: &Parser) -> Result<(), String> {
    if let Some(name) = &parser.active {
        Err(format!("record while test is active: {name}"))
    } else {
        Ok(())
    }
}

fn completion_name<'a, I>(parser: &mut Parser, words: &mut I) -> Result<String, String>
where
    I: Iterator<Item = &'a str>,
{
    let name = completion_name_first(parser, words)?;
    no_more(words.by_ref())?;
    finish_completion(parser, &name)?;
    Ok(name)
}

fn completion_name_first<'a, I>(parser: &Parser, words: &mut I) -> Result<String, String>
where
    I: Iterator<Item = &'a str>,
{
    let name = protocol_name(
        one_word(words, "test completion name")?,
        "test completion name",
    )?
    .to_owned();
    match parser.active.as_deref() {
        Some(active) if active == name => Ok(name),
        Some(active) => Err(format!("completion for {name} while {active} is active")),
        None => Err(format!("completion without RUN: {name}")),
    }
}

fn finish_completion(parser: &mut Parser, name: &str) -> Result<(), String> {
    if !parser.completed.insert(name.to_owned()) {
        return Err(format!("duplicate test completion: {name}"));
    }
    parser.active = None;
    Ok(())
}

fn required_reason<'a, I>(mut words: I) -> Result<String, String>
where
    I: Iterator<Item = &'a str>,
{
    let raw = words.next().ok_or("missing reason field")?;
    let (key, value) = split_field(raw)?;
    if key != "reason" || value.is_empty() {
        return Err("expected non-empty reason field".into());
    }
    no_more(words)?;
    Ok(value.into())
}

fn numeric_field<'a, I>(words: &mut I, key: &str) -> Result<u32, String>
where
    I: Iterator<Item = &'a str>,
{
    one_field(words, key)?
        .parse::<u32>()
        .map_err(|_| format!("invalid {key} counter"))
}

fn one_field<'a, I>(words: &mut I, key: &str) -> Result<&'a str, String>
where
    I: Iterator<Item = &'a str>,
{
    let raw = words.next().ok_or_else(|| format!("missing {key} field"))?;
    let (actual, value) = split_field(raw)?;
    if actual != key || value.is_empty() {
        return Err(format!("expected non-empty {key} field"));
    }
    Ok(value)
}

fn split_field(raw: &str) -> Result<(&str, &str), String> {
    raw.split_once('=')
        .ok_or_else(|| format!("malformed field: {raw}"))
}

fn one_word<'a, I>(words: &mut I, description: &str) -> Result<&'a str, String>
where
    I: Iterator<Item = &'a str>,
{
    words
        .next()
        .filter(|word| !word.is_empty() && !word.contains('='))
        .ok_or_else(|| format!("missing or invalid {description}"))
}

fn protocol_name<'a>(value: &'a str, description: &str) -> Result<&'a str, String> {
    if value.len() > TEST_NAME_LIMIT
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(format!(
            "invalid {description}; expected at most {TEST_NAME_LIMIT} ASCII name bytes"
        ));
    }
    Ok(value)
}

fn no_more<'a, I>(mut words: I) -> Result<(), String>
where
    I: Iterator<Item = &'a str>,
{
    match words.next() {
        Some(extra) => Err(format!("unexpected field: {extra}")),
        None => Ok(()),
    }
}
