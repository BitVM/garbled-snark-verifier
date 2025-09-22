use tracing::info;

/// Step for periodic gate progress logs.
pub const GATE_LOG_STEP: usize = 50_000_000;

/// Format a gate count with compact suffixes: k, m, b, t.
#[inline]
pub fn format_gate_count(n: u64) -> String {
    const THOUSAND: u64 = 1_000;
    const MILLION: u64 = 1_000_000;
    const BILLION: u64 = 1_000_000_000;
    const TRILLION: u64 = 1_000_000_000_000;

    match n {
        v if v >= TRILLION => format!("{:.2}t", v as f64 / TRILLION as f64),
        v if v >= BILLION => format!("{:.2}b", v as f64 / BILLION as f64),
        v if v >= MILLION => format!("{:.1}m", v as f64 / MILLION as f64),
        v if v >= THOUSAND => format!("{:.1}k", v as f64 / THOUSAND as f64),
        _ => format!("{}", n),
    }
}

/// Log progress every `GATE_LOG_STEP` gates with a unified format.
#[inline]
pub fn maybe_log_progress(label: &str, gate_id: usize) {
    if gate_id.is_multiple_of(GATE_LOG_STEP) {
        info!("{}: {}", label, format_gate_count(gate_id as u64));
    }
}
