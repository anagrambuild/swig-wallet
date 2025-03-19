pub struct SolLimit {
    pub amount: u64
}

pub struct SolRecurringLimit {
    pub recurring_amount: u64,
    pub window: u64,
    pub last_reset: u64,
    pub current_amount: u64,
}



