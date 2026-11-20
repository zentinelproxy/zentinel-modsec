//! Helpers shared by integration tests.

use std::cell::RefCell;
use std::io;
use std::sync::Once;

thread_local! {
    /// What the calling thread has logged since its last capture began.
    static LOG: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

struct ThreadLog;

impl io::Write for ThreadLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        LOG.with(|log| log.borrow_mut().extend_from_slice(bytes));
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Run `load` and return its result with what the calling thread logged
/// meanwhile, one formatted event per line.
///
/// The subscriber is installed for the whole process and writes to a buffer
/// per thread. A subscriber scoped to the calling thread is not enough: when
/// another test thread reaches a log statement first, tracing caches that
/// nobody listens to it and the scoped subscriber never sees the event.
pub fn capture_log<T>(load: impl FnOnce() -> T) -> (T, String) {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(|| ThreadLog)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other subscriber is installed in a test binary");
    });
    LOG.with(|log| log.borrow_mut().clear());
    let result = load();
    let logged = LOG.with(|log| std::mem::take(&mut *log.borrow_mut()));
    (
        result,
        String::from_utf8(logged).expect("log output is UTF-8"),
    )
}
