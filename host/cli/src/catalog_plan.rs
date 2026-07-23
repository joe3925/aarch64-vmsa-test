use crate::args::Target;

const REGISTRY: &str = include_str!("../../../target/harness/src/registry.rs");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Isolation {
    Sequential,
    Separate,
    Destructive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootPlan {
    pub filter: Option<String>,
    pub expects_termination: bool,
    pub test_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogCase {
    name: String,
    targets: [bool; 5],
    applicable: [bool; 5],
    isolation: Isolation,
    expects_termination: bool,
}

pub fn validate() -> Result<(), String> {
    let cases = parse_registry()?;
    if cases.is_empty() {
        return Err("typed registry contains no logical tests".into());
    }
    for (index, case) in cases.iter().enumerate() {
        if !case.targets.iter().any(|value| *value) {
            return Err(format!(
                "registry case {} has no adapter handler",
                case.name
            ));
        }
        for target in 0..case.targets.len() {
            if case.applicable[target] && !case.targets[target] {
                return Err(format!(
                    "registry case {} is applicable to adapter {} but has no handler",
                    case.name, target
                ));
            }
            if !case.applicable[target] && case.targets[target] {
                return Err(format!(
                    "registry case {} has a handler for inapplicable adapter {}",
                    case.name, target
                ));
            }
        }
        if cases[..index].iter().any(|other| other.name == case.name) {
            return Err(format!("duplicate registry case {}", case.name));
        }
    }
    Ok(())
}

pub fn plan(target: Target, filter: Option<&str>) -> Result<Vec<BootPlan>, String> {
    let cases = parse_registry()?;
    let target_index = match target {
        Target::NsEl2 => 0,
        Target::SecureEl2 => 1,
        Target::RealmEl2 => 2,
        Target::RealmStage2 => 3,
        Target::RootEl3 => 4,
    };
    let exact = filter.is_some_and(|wanted| {
        cases
            .iter()
            .any(|case| case.targets[target_index] && case.name == wanted)
    });
    let selected = |case: &&CatalogCase| {
        case.targets[target_index]
            && filter.is_none_or(|wanted| {
                if exact {
                    case.name == wanted
                } else {
                    case.name.contains(wanted)
                }
            })
    };
    let mut plans = Vec::new();
    let sequential_count = cases
        .iter()
        .filter(selected)
        .filter(|case| case.isolation == Isolation::Sequential)
        .count();
    if sequential_count != 0 {
        plans.push(BootPlan {
            filter: filter.map(str::to_owned),
            expects_termination: false,
            test_count: sequential_count,
        });
    }
    for case in cases
        .iter()
        .filter(selected)
        .filter(|case| matches!(case.isolation, Isolation::Separate | Isolation::Destructive))
    {
        plans.push(BootPlan {
            filter: Some(case.name.clone()),
            expects_termination: case.expects_termination,
            test_count: 1,
        });
    }
    Ok(plans)
}

fn parse_registry() -> Result<Vec<CatalogCase>, String> {
    let mut cases = Vec::new();
    for source_line in REGISTRY.lines() {
        let line = source_line.trim();
        if !line.ends_with(';') || !line.contains("\"") || !line.contains("), (") {
            continue;
        }
        let fields = split_top_level(&line[..line.len() - 1])?;
        if fields.len() != 8 {
            return Err(format!(
                "registry row has {} fields rather than 8: {line}",
                fields.len()
            ));
        }
        let name = fields[1]
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| format!("registry row has invalid name: {line}"))?
            .to_owned();
        let builder = fields[2];
        let applicable = applicable_targets(builder)?;
        let isolation = if builder.contains("IsolationPolicy::DestructiveBoot") {
            Isolation::Destructive
        } else if builder.contains("IsolationPolicy::SeparateBoot") {
            Isolation::Separate
        } else {
            Isolation::Sequential
        };
        let expects_termination = isolation == Isolation::Destructive;
        let mut targets = [false; 5];
        for (slot, handler) in targets.iter_mut().zip(&fields[3..]) {
            *slot = handler.trim() != "(none)";
        }
        cases.push(CatalogCase {
            name,
            targets,
            applicable,
            isolation,
            expects_termination,
        });
    }
    Ok(cases)
}

fn applicable_targets(builder: &str) -> Result<[bool; 5], String> {
    let start = builder
        .find('(')
        .ok_or_else(|| format!("registry builder has no arguments: {builder}"))?
        + 1;
    let arguments = split_top_level(
        builder
            .get(start..builder.len().saturating_sub(1))
            .ok_or_else(|| format!("registry builder is malformed: {builder}"))?,
    )?;
    let environments = arguments
        .first()
        .ok_or_else(|| format!("registry builder has no environment: {builder}"))?;
    let mut targets = match *environments {
        "NORMAL" => [true, false, false, false, false],
        "NORMAL_SECURE" => [true, true, false, false, false],
        "NORMAL_ROOT" => [true, false, false, false, true],
        "NORMAL_SECURE_REALM" => [true, true, true, true, false],
        "NORMAL_SECURE_REALM_ROOT" | "ALL_ENVIRONMENTS" => [true; 5],
        "SecurityEnvironments::SECURE" => [false, true, false, false, false],
        "SecurityEnvironments::SECURE.union(SecurityEnvironments::REALM)" => {
            [false, true, true, true, false]
        }
        "NORMAL.union(SecurityEnvironments::SECURE).union(SecurityEnvironments::REALM)" => {
            [true, true, true, true, false]
        }
        "NORMAL.union(SecurityEnvironments::REALM)" => [true, false, true, true, false],
        "SecurityEnvironments::REALM" => [false, false, true, true, false],
        "SecurityEnvironments::ROOT" => [false, false, false, false, true],
        "NORMAL_SECURE.union(SecurityEnvironments::REALM)" => [true, true, true, true, false],
        other => return Err(format!("unknown registry environment expression: {other}")),
    };
    if builder.contains("NON_REC_PROFILES") {
        targets[3] = false;
    }
    if builder.contains("BootProfile::RealmRecStage2") {
        targets = [false, false, false, true, false];
    } else if builder.contains("BootProfile::RealmEl2") {
        targets = [false, false, true, false, false];
    }
    Ok(targets)
}

fn split_top_level(line: &str) -> Result<Vec<&str>, String> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut depth = 0u32;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in line.bytes().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'(' => depth = depth.saturating_add(1),
            b')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| format!("unbalanced registry row: {line}"))?;
            }
            b',' if depth == 0 => {
                fields.push(line[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if quoted || depth != 0 {
        return Err(format!("unterminated registry row: {line}"));
    }
    fields.push(line[start..].trim());
    Ok(fields)
}
