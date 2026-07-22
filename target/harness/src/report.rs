#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportEvent {
    Begin {
        target: &'static str,
    },
    Capability {
        name: &'static str,
        value: u64,
    },
    Run {
        name: &'static str,
    },
    Pass {
        name: &'static str,
    },
    Fail {
        name: &'static str,
        reason: &'static str,
        expected: u64,
        actual: u64,
    },
    InfrastructureFailure {
        name: &'static str,
        reason: &'static str,
        expected: u64,
        actual: u64,
    },
    Skip {
        name: &'static str,
        reason: &'static str,
    },
    End {
        passed: u32,
        failed: u32,
        skipped: u32,
    },
}

pub trait ByteSink {
    fn write_byte(&mut self, byte: u8);
}

pub struct ProtocolWriter<S> {
    sink: S,
}
const PROTOCOL_VERSION: u32 = 1;

impl<S: ByteSink> ProtocolWriter<S> {
    pub const fn new(sink: S) -> Self {
        Self { sink }
    }
    pub fn emit(&mut self, event: ReportEvent) {
        use core::fmt::Write;
        match event {
            ReportEvent::Begin { target } => writeln!(
                self,
                "@@VMSA BEGIN protocol={PROTOCOL_VERSION} target={target}"
            ),
            ReportEvent::Capability { name, value } => writeln!(self, "@@VMSA CAP {name}={value}"),
            ReportEvent::Run { name } => writeln!(self, "@@VMSA RUN {name}"),
            ReportEvent::Pass { name } => writeln!(self, "@@VMSA PASS {name}"),
            ReportEvent::Fail {
                name,
                reason,
                expected,
                actual,
            } => {
                writeln!(
                    self,
                    "@@VMSA FAIL {name} reason={reason} expected={expected} actual={actual}"
                )
            }
            ReportEvent::InfrastructureFailure {
                name,
                reason,
                expected,
                actual,
            } => writeln!(
                self,
                "@@VMSA INFRA {name} reason={reason} expected={expected} actual={actual}"
            ),
            ReportEvent::Skip { name, reason } => {
                writeln!(self, "@@VMSA SKIP {name} reason={reason}")
            }
            ReportEvent::End {
                passed,
                failed,
                skipped,
            } => writeln!(
                self,
                "@@VMSA END passed={passed} failed={failed} skipped={skipped}"
            ),
        }
        .expect("ProtocolWriter formatting through ByteSink is infallible");
    }
}

impl<S: ByteSink> core::fmt::Write for ProtocolWriter<S> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        for byte in text.bytes() {
            self.sink.write_byte(byte);
        }
        Ok(())
    }
}
