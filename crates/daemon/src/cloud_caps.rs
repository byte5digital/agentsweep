//! The cloud caps on the Claude engine (spec section 4.4): at most the
//! setting's Items per day and money per month, on top of the per-Scan cap
//! the AI Judgement queue applies to every engine.
//!
//! Before each request to the Claude API starts, the queue asks the daemon
//! whether it may: a request that would start past a cap is not sent, the
//! Item gets no Verdict, and the queue holds back everything still pending
//! for the next Scan, which counts as the cap notice. Each answer the API was
//! billed for writes one `judgement-spend` record beside the events in the
//! Event Log, priced from the table in the binary; the counters are rebuilt
//! from those records at start, so a restart or a rebuilt state file keeps
//! the day's and the month's counts. Local engines are never metered.
//!
//! The day and the month are calendar ones in the Mac's local time zone, as
//! the [`Calendar`] says; a test hands in one of its own.

use std::time::{SystemTime, UNIX_EPOCH};

use agentsweep_core::eventlog::EventLog;
use agentsweep_core::judgement::Usage;
use agentsweep_core::keychain::KeySource;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::settings::JudgementSettings;
use agentsweep_core::spend::{
    CapNotice, JudgementCap, LocalDate, SpendLedger, SpendRecord, price_of,
};
use agentsweep_ipc::engine::CloudUse;

use crate::service::Daemon;
use crate::stores::open_the_event_log;

/// Where the daemon reads today's date.
pub trait Calendar: Send + Sync {
    /// Today, in the Mac's local time zone.
    fn today(&self) -> LocalDate;
}

/// The Mac's own clock and time zone.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCalendar;

impl Calendar for SystemCalendar {
    fn today(&self) -> LocalDate {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or_default();
        let now = libc::time_t::try_from(seconds).unwrap_or_default();
        // SAFETY: `tm` is plain data that `localtime_r` fills in; both
        // pointers are valid for the call, and the reentrant variant keeps no
        // state of its own.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let filled = unsafe { libc::localtime_r(&now, &mut tm) };
        if filled.is_null() {
            return LocalDate::new(1970, 1, 1);
        }
        LocalDate::new(
            u16::try_from(tm.tm_year + 1900).unwrap_or(1970),
            u8::try_from(tm.tm_mon + 1).unwrap_or(1),
            u8::try_from(tm.tm_mday).unwrap_or(1),
        )
    }
}

/// The counters the cloud caps read: the ledger rebuilt from the Event Log,
/// and the requests started and not yet answered.
#[derive(Debug, Default)]
pub struct CloudLedger {
    ledger: SpendLedger,
    reserved: u32,
}

impl CloudLedger {
    /// The counters the Event Log in this data directory adds up to. A log
    /// that cannot be read counts as nothing spent, and says so.
    pub fn in_the_event_log(directory: &DataDirectory, keys: &dyn KeySource) -> CloudLedger {
        let ledger = match EventLog::in_data_directory(directory).read(keys) {
            Ok(view) => view.spend_ledger(),
            Err(error) => {
                say!("the cloud spend could not be read from the Event Log: {error}");
                SpendLedger::default()
            }
        };
        CloudLedger {
            ledger,
            reserved: 0,
        }
    }
}

impl Daemon {
    fn ledger(&self) -> std::sync::MutexGuard<'_, CloudLedger> {
        self.spend
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Whether one more request to the Claude API may start now. One that
    /// may is counted as started until its answer is settled; one that would
    /// start past a cap is refused with the cap.
    pub(crate) fn admit_a_cloud_request(&self) -> Result<(), JudgementCap> {
        let caps = self.judgement().caps;
        let today = self.tuning.calendar.today();
        let mut held = self.ledger();
        if let Some(cap) = held.ledger.refused(today, held.reserved, &caps) {
            return Err(cap);
        }
        held.reserved += 1;
        Ok(())
    }

    /// Settles one request to the Claude API that was admitted: it is no
    /// longer counted as started, and when the API reported its usage, one
    /// `judgement-spend` record is written and counted. The caller holds the
    /// write lock.
    pub(crate) fn settle_a_cloud_request(&self, model: &str, usage: Option<Usage>) {
        let record =
            usage.map(|usage| SpendRecord::priced(self.tuning.calendar.today(), model, usage));
        {
            let mut held = self.ledger();
            held.reserved = held.reserved.saturating_sub(1);
            if let Some(record) = &record {
                held.ledger.add(record);
            }
        }
        let Some(record) = record else {
            return;
        };
        let written = open_the_event_log(&self.directory, &*self.keys)
            .and_then(|(mut writer, _)| writer.record_judgement_spend(&record));
        if let Err(error) = written {
            say!("the spend of a request to the Claude API could not be recorded: {error}");
        }
    }

    /// Where the cloud caps stand: today's Items, this month's spend, whether
    /// the Claude model in use is priced, and the cap notice.
    pub fn cloud_use(&self) -> CloudUse {
        self.cloud_use_of(&self.judgement())
    }

    /// The same, under these AI Judgement choices.
    pub(crate) fn cloud_use_of(&self, judgement: &JudgementSettings) -> CloudUse {
        let today = self.tuning.calendar.today();
        let model = judgement.claude_model_in_use();
        let (items_today, microdollars_this_month) = {
            let held = self.ledger();
            (
                held.ledger.items_on(today),
                held.ledger.spent_in_month_of(today),
            )
        };
        CloudUse {
            items_today,
            microdollars_this_month,
            model_priced: price_of(model).1,
            judgement_cap: self
                .health
                .lock()
                .expect("the health is not poisoned")
                .judgement_cap,
        }
    }

    /// Records the cap notice the queue reports, absent once nothing waits,
    /// and tells every subscriber when it moved.
    pub(crate) fn note_the_cap(&self, notice: Option<CapNotice>) {
        {
            let mut health = self.health.lock().expect("the health is not poisoned");
            if health.judgement_cap == notice {
                return;
            }
            health.judgement_cap = notice;
        }
        if let Some(notice) = notice {
            say!(
                "the AI check reached its {} cap: {} Items will be looked at next time",
                notice.cap,
                notice.waiting
            );
        }
        self.tell_health();
    }
}
