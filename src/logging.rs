use std::sync::OnceLock;

use tracing_log::LogTracer;
use tracing_subscriber::{
    EnvFilter,
    fmt::{self, time::SystemTime},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

static INSTALL_GUARD: OnceLock<()> = OnceLock::new();

/// Initialize global tracing subscriber with env-based filtering and thread scopes.
pub fn init_tracing() {
    INSTALL_GUARD.get_or_init(|| {
        if LogTracer::init().is_err() {
            // Already installed or logging disabled; continue.
        }

        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        let fmt_layer = fmt::layer()
            .with_timer(SystemTime)
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_ansi(false)
            .compact();

        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer);

        if subscriber.try_init().is_err() {
            // Global subscriber already installed elsewhere; ignore.
        }
    });
}
