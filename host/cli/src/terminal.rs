use std::io::{self, IsTerminal};

#[derive(Clone, Copy)]
pub(crate) enum Tone {
    Success,
    Failure,
    Skipped,
    Active,
    Muted,
}

impl Tone {
    const fn ansi(self) -> &'static str {
        match self {
            Self::Success => "\x1b[32m",
            Self::Failure => "\x1b[31m",
            Self::Skipped => "\x1b[33m",
            Self::Active => "\x1b[36m",
            Self::Muted => "\x1b[2m",
        }
    }
}

pub(crate) fn stdout_has_color() -> bool {
    color_allowed() && io::stdout().is_terminal()
}

pub(crate) fn stderr_has_color() -> bool {
    color_allowed() && io::stderr().is_terminal()
}

pub(crate) fn stderr_is_terminal() -> bool {
    io::stderr().is_terminal()
}

pub(crate) fn paint(enabled: bool, tone: Tone, text: &str) -> String {
    if enabled {
        format!("{}{text}\x1b[0m", tone.ansi())
    } else {
        text.to_owned()
    }
}

fn color_allowed() -> bool {
    std::env::var_os("NO_COLOR").is_none()
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}
