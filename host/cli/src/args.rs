use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    NsEl2,
    SecureEl2,
    RealmEl2,
    RealmStage2,
    RootEl3,
}

impl Target {
    pub const ALL: [Self; 5] = [
        Self::NsEl2,
        Self::SecureEl2,
        Self::RealmEl2,
        Self::RealmStage2,
        Self::RootEl3,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NsEl2 => "ns-el2",
            Self::SecureEl2 => "secure-el2",
            Self::RealmEl2 => "realm-el2",
            Self::RealmStage2 => "realm-stage2",
            Self::RootEl3 => "root-el3",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "ns-el2" => Some(Self::NsEl2),
            "secure-el2" => Some(Self::SecureEl2),
            "realm-el2" => Some(Self::RealmEl2),
            "realm-stage2" => Some(Self::RealmStage2),
            "root-el3" => Some(Self::RootEl3),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum Command {
    Doctor,
    Test(Vec<Target>),
    Clean,
}

#[derive(Debug)]
pub struct Args {
    pub command: Command,
    pub crate_path: Option<PathBuf>,
    pub filter: Option<String>,
    pub keep: bool,
}

impl Args {
    pub fn parse() -> Result<Self, String> {
        Self::parse_from(std::env::args().skip(1))
    }

    fn parse_from<I>(arguments: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut values = arguments.into_iter().peekable();
        let command_name = values.next().ok_or_else(usage)?;
        let mut target = None;
        if command_name == "test" {
            target = Some(values.next().ok_or_else(usage)?);
        }

        let mut crate_path = None;
        let mut filter = None;
        let mut keep = false;
        while let Some(argument) = values.next() {
            match argument.as_str() {
                "--crate" => {
                    let value = values.next().ok_or("--crate requires a path")?;
                    if crate_path.replace(PathBuf::from(value)).is_some() {
                        return Err("--crate may be specified only once".into());
                    }
                }
                "--filter" => {
                    let value = values.next().ok_or("--filter requires a substring")?;
                    if value.is_empty() {
                        return Err("--filter cannot be empty".into());
                    }
                    if value.len() > crate::settings::FILTER_LIMIT
                        || value.chars().any(char::is_control)
                    {
                        return Err(format!(
                            "--filter must be at most {} bytes and contain no control characters",
                            crate::settings::FILTER_LIMIT
                        ));
                    }
                    if filter.replace(value).is_some() {
                        return Err("--filter may be specified only once".into());
                    }
                }
                "--keep" if !keep => keep = true,
                unknown => return Err(format!("unknown argument: {unknown}\n{}", usage())),
            }
        }

        let command = match command_name.as_str() {
            "doctor" if target.is_none() => Command::Doctor,
            "clean" if target.is_none() => Command::Clean,
            "test" => match target.as_deref() {
                Some("all") => Command::Test(Target::ALL.to_vec()),
                Some(value) => Command::Test(vec![
                    Target::parse(value).ok_or_else(|| format!("unknown test target: {value}"))?,
                ]),
                None => return Err(usage()),
            },
            _ => return Err(usage()),
        };

        if !matches!(command, Command::Test(_)) && (filter.is_some() || keep) {
            return Err("--filter and --keep are valid only with test".into());
        }
        match &command {
            Command::Doctor | Command::Test(_) if crate_path.is_none() => {
                return Err("--crate <path> is required for doctor and test".into());
            }
            Command::Clean if crate_path.is_some() => {
                return Err("--crate is not valid with clean".into());
            }
            _ => {}
        }

        Ok(Self {
            command,
            crate_path,
            filter,
            keep,
        })
    }
}

fn usage() -> String {
    "usage: vmsa-test doctor --crate <path>\n       vmsa-test test <ns-el2|secure-el2|realm-el2|realm-stage2|root-el3|all> --crate <path> [--filter <substring>] [--keep]\n       vmsa-test clean".into()
}
