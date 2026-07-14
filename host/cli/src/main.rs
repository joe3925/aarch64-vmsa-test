use vmsa_test::args::Args;
use vmsa_test::run::{self, ExitCode};

fn main() {
    let code = match Args::parse() {
        Ok(args) => run::execute(args),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::InvalidSetup
        }
    };
    std::process::exit(code as i32);
}
