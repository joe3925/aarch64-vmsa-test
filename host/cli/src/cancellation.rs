use std::sync::atomic::{AtomicBool, Ordering};

static REQUESTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn install() -> Result<(), String> {
    ctrlc::set_handler(|| REQUESTED.store(true, Ordering::Release))
        .map_err(|error| format!("cannot install cancellation handler: {error}"))
}

pub(crate) fn requested() -> bool {
    REQUESTED.load(Ordering::Acquire)
}
