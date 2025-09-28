#[derive(Debug, Clone)]
pub struct Stats {
    pub messages_sent: u32,
    pub messages_failed: u32,
    pub bytes_sent: u64,
    pub start_time: std::time::Instant,
    pub last_update: std::time::Instant,
    pub connection_errors: u32,
}

impl Stats {
    pub fn new() -> Self {
        let now = std::time::Instant::now();
        Stats {
            messages_sent: 0,
            messages_failed: 0,
            bytes_sent: 0,
            start_time: now,
            last_update: now,
            connection_errors: 0,
        }
    }
}