use std::io::Write;

use clap::CommandFactory;
use clap_complete::{generate, Shell};

use crate::Cli;

/// Generate shell completions for nat-gate
pub fn run(shell: Shell) -> Result<(), String> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();

    // Generate into memory, then write once: piping into `head`/`less`
    // closes stdout early and clap_complete's internal unwrap panics on
    // the resulting BrokenPipe. A truncated consumer (head) is a success;
    // any other write error is reported as usual.
    let mut buf: Vec<u8> = Vec::new();
    generate(shell, &mut cmd, name, &mut buf);

    let mut stdout = std::io::stdout();
    if let Err(e) = stdout.write_all(&buf).and_then(|()| stdout.flush()) {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(format!("Failed to write completions: {e}"));
        }
    }

    Ok(())
}
