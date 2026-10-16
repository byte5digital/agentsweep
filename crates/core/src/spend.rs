//! What AI Judgement spends on the Claude API, and the cloud caps it is held
//! to (spec section 4.4, "Caps, cache, CLI").
//!
//! Every cloud request the API answered with a `usage` writes one
//! `judgement-spend` record beside the events in the Event Log: the calendar
//! day it was asked on, the model, the input and output tokens the API
//! reported and what they cost under the price table in this binary. Never
//! content, never a key. The counters the caps read, Items asked today and
//! money spent this month, are a derived view rebuilt from those records, so
//! a rebuilt state file cannot reset them.
//!
//! The day and the month are calendar ones in the Mac's local time zone. The
//! record carries its day as the local date it was asked on, so the view is
//! counted from the records alone.
//!
//! A model the price table does not name (a Developer override) is priced at
//! the most expensive model in the table, and the engine state says so: a
//! request is never sent unpriced.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Map, Value};

use crate::judgement::Usage;
use crate::settings::CloudCaps;

/// One model's price, in US cents per million tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Price {
    /// The model id the Claude API knows it by.
    pub model: &'static str,
    /// Cents per million input tokens.
    pub input_cents_per_million: u64,
    /// Cents per million output tokens.
    pub output_cents_per_million: u64,
}

impl Price {
    /// What `usage` costs at this price, in millionths of a dollar, rounded
    /// up so the counters never fall behind what the API bills.
    pub fn cost(&self, usage: Usage) -> u64 {
        // One cent per million tokens is a hundredth of a microdollar per
        // token.
        let hundredths = usage
            .input_tokens
            .saturating_mul(self.input_cents_per_million)
            .saturating_add(
                usage
                    .output_tokens
                    .saturating_mul(self.output_cents_per_million),
            );
        hundredths.div_ceil(100)
    }
}

/// The price table in this binary: every model AI Judgement is priced at.
pub const PRICES: &[Price] = &[Price {
    model: "claude-sonnet-5",
    input_cents_per_million: 200,
    output_cents_per_million: 1_000,
}];

/// The price `model` is counted at, and whether the table names it. A model
/// it does not name is counted at the most expensive one in the table.
pub fn price_of(model: &str) -> (Price, bool) {
    match PRICES.iter().find(|price| price.model == model) {
        Some(price) => (*price, true),
        None => (most_expensive(), false),
    }
}

fn most_expensive() -> Price {
    *PRICES
        .iter()
        .max_by_key(|price| {
            (
                price.output_cents_per_million,
                price.input_cents_per_million,
            )
        })
        .expect("the price table names a model")
}

/// A calendar day in the Mac's local time zone.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LocalDate {
    /// The year, four digits.
    pub year: u16,
    /// The month, 1 to 12.
    pub month: u8,
    /// The day of the month, 1 to 31.
    pub day: u8,
}

impl LocalDate {
    /// The day of `year`, `month` and `day`.
    pub fn new(year: u16, month: u8, day: u8) -> LocalDate {
        LocalDate { year, month, day }
    }

    /// Reads back `YYYY-MM-DD`.
    pub fn parse(text: &str) -> Option<LocalDate> {
        let mut parts = text.split('-');
        let year = parts.next()?;
        let month = parts.next()?;
        let day = parts.next()?;
        if parts.next().is_some() || year.len() != 4 || month.len() != 2 || day.len() != 2 {
            return None;
        }
        let date = LocalDate {
            year: year.parse().ok()?,
            month: month.parse().ok()?,
            day: day.parse().ok()?,
        };
        ((1..=12).contains(&date.month) && (1..=31).contains(&date.day)).then_some(date)
    }

    fn same_month(&self, other: &LocalDate) -> bool {
        self.year == other.year && self.month == other.month
    }
}

impl fmt::Display for LocalDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// One cloud request, the payload of a `judgement-spend` record. It carries
/// what the request cost and nothing of what it asked about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendRecord {
    /// The local calendar day it was asked on.
    pub date: LocalDate,
    /// The model it asked.
    pub model: String,
    /// The input tokens the API reported.
    pub input_tokens: u64,
    /// The output tokens the API reported.
    pub output_tokens: u64,
    /// What they cost under the price table, in millionths of a dollar.
    pub cost_microdollars: u64,
}

impl SpendRecord {
    /// The record of one request to `model` on `date` that used `usage`,
    /// priced from the table.
    pub fn priced(date: LocalDate, model: &str, usage: Usage) -> SpendRecord {
        let (price, _) = price_of(model);
        SpendRecord {
            date,
            model: model.to_string(),
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cost_microdollars: price.cost(usage),
        }
    }

    /// The payload a record carries.
    pub fn to_payload(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "cost_microdollars".to_string(),
            Value::from(self.cost_microdollars),
        );
        map.insert("date".to_string(), Value::from(self.date.to_string()));
        map.insert("input_tokens".to_string(), Value::from(self.input_tokens));
        map.insert("model".to_string(), Value::from(self.model.as_str()));
        map.insert("output_tokens".to_string(), Value::from(self.output_tokens));
        Value::Object(map)
    }

    /// Reads back the payload a record carries.
    pub fn from_payload(payload: &Value) -> Option<SpendRecord> {
        let number = |field: &str| payload.get(field).and_then(Value::as_u64);
        Some(SpendRecord {
            date: LocalDate::parse(payload.get("date")?.as_str()?)?,
            model: payload.get("model")?.as_str()?.to_string(),
            input_tokens: number("input_tokens")?,
            output_tokens: number("output_tokens")?,
            cost_microdollars: number("cost_microdollars")?,
        })
    }
}

/// The cap that held AI Judgement back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JudgementCap {
    /// The Items one Scan may hand the engine.
    Scan,
    /// The Items the Claude API may be asked about in one day.
    Day,
    /// The money the Claude API may be paid in one month.
    Month,
}

impl JudgementCap {
    /// The spelling the wire carries.
    pub fn as_str(self) -> &'static str {
        match self {
            JudgementCap::Scan => "scan",
            JudgementCap::Day => "day",
            JudgementCap::Month => "month",
        }
    }

    /// Reads back the spelling the wire carries.
    pub fn parse(text: &str) -> Option<JudgementCap> {
        match text {
            "scan" => Some(JudgementCap::Scan),
            "day" => Some(JudgementCap::Day),
            "month" => Some(JudgementCap::Month),
            _ => None,
        }
    }
}

impl fmt::Display for JudgementCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The cap notice: a cap held Items back, and how many are waiting to be
/// asked by the next Scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapNotice {
    /// The cap that held them back, the last one when several did.
    pub cap: JudgementCap,
    /// How many Items are waiting.
    pub waiting: usize,
}

impl CapNotice {
    /// The fixed line every Posture shows (spec section 4.4).
    pub fn line(&self) -> String {
        match self.waiting {
            1 => "The AI check reached its limit for this scan. 1 item will be looked at next \
                  time."
                .to_string(),
            waiting => format!(
                "The AI check reached its limit for this scan. {waiting} items will be looked \
                 at next time."
            ),
        }
    }
}

/// The counters the cloud caps read, rebuilt from the `judgement-spend`
/// records: how many Items were asked and what they cost, per local day.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpendLedger {
    days: BTreeMap<LocalDate, (u32, u64)>,
}

impl SpendLedger {
    /// The ledger the records add up to.
    pub fn of<'r>(records: impl IntoIterator<Item = &'r SpendRecord>) -> SpendLedger {
        let mut ledger = SpendLedger::default();
        for record in records {
            ledger.add(record);
        }
        ledger
    }

    /// Counts one more record.
    pub fn add(&mut self, record: &SpendRecord) {
        let (items, cost) = self.days.entry(record.date).or_default();
        *items = items.saturating_add(1);
        *cost = cost.saturating_add(record.cost_microdollars);
    }

    /// The Items asked on `today`.
    pub fn items_on(&self, today: LocalDate) -> u32 {
        self.days.get(&today).map_or(0, |(items, _)| *items)
    }

    /// What was spent in the calendar month of `today`, in millionths of a
    /// dollar.
    pub fn spent_in_month_of(&self, today: LocalDate) -> u64 {
        self.days
            .iter()
            .filter(|(day, _)| day.same_month(&today))
            .map(|(_, (_, cost))| *cost)
            .fold(0, u64::saturating_add)
    }

    /// The cap a request that would start now, on `today`, runs past, or
    /// None when it may be sent. `reserved` are requests already started and
    /// not yet answered: each counts as an Item of the day.
    pub fn refused(
        &self,
        today: LocalDate,
        reserved: u32,
        caps: &CloudCaps,
    ) -> Option<JudgementCap> {
        if self.items_on(today).saturating_add(reserved) >= caps.items_per_day {
            return Some(JudgementCap::Day);
        }
        let cap = u64::from(caps.cents_per_month).saturating_mul(10_000);
        (self.spent_in_month_of(today) >= cap).then_some(JudgementCap::Month)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(input_tokens: u64, output_tokens: u64) -> Usage {
        Usage {
            input_tokens,
            output_tokens,
        }
    }

    #[test]
    fn sonnet_is_priced_at_two_and_ten_dollars_per_million_tokens() {
        let (price, known) = price_of("claude-sonnet-5");
        assert!(known);
        assert_eq!(price.cost(usage(1_000_000, 0)), 2_000_000);
        assert_eq!(price.cost(usage(0, 1_000_000)), 10_000_000);
        assert_eq!(price.cost(usage(1_234, 56)), 2_468 + 560);
        assert_eq!(price.cost(usage(1, 0)), 2);
        // A part of a microdollar is counted as a whole one.
        let cheap = Price {
            model: "cheap",
            input_cents_per_million: 1,
            output_cents_per_million: 1,
        };
        assert_eq!(cheap.cost(usage(1, 0)), 1);
    }

    #[test]
    fn an_unknown_model_is_priced_at_the_most_expensive_one_in_the_table() {
        let (price, known) = price_of("claude-something-else");
        assert!(!known);
        let dearest = PRICES
            .iter()
            .map(|price| price.output_cents_per_million)
            .max();
        assert_eq!(Some(price.output_cents_per_million), dearest);
        let record = SpendRecord::priced(LocalDate::new(2026, 10, 16), "custom", usage(0, 1_000));
        assert_eq!(record.model, "custom");
        assert_eq!(record.cost_microdollars, 10_000);
    }

    /// The record carries the day, the model, the tokens and the cost, and
    /// nothing else: no content and no key.
    #[test]
    fn a_spend_record_round_trips_and_carries_nothing_else() {
        let record = SpendRecord::priced(
            LocalDate::new(2026, 10, 16),
            "claude-sonnet-5",
            usage(1_234, 56),
        );
        let payload = record.to_payload();
        let keys: Vec<&str> = payload
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![
                "cost_microdollars",
                "date",
                "input_tokens",
                "model",
                "output_tokens"
            ]
        );
        assert_eq!(payload["date"], "2026-10-16");
        assert_eq!(SpendRecord::from_payload(&payload), Some(record));
        assert_eq!(SpendRecord::from_payload(&Value::Null), None);
    }

    #[test]
    fn dates_read_back_only_as_written() {
        assert_eq!(
            LocalDate::parse("2026-01-09"),
            Some(LocalDate::new(2026, 1, 9))
        );
        for bad in ["2026-1-09", "2026-13-01", "2026-01-00", "2026-01-09-1", ""] {
            assert_eq!(LocalDate::parse(bad), None, "{bad}");
        }
    }

    /// The 201st Item of a day is refused, the next day's first is not; a
    /// request already on its way counts as an Item of the day.
    #[test]
    fn the_day_cap_counts_items_per_local_day() {
        let caps = CloudCaps::default();
        let today = LocalDate::new(2026, 10, 16);
        let records: Vec<SpendRecord> = (0..199)
            .map(|_| SpendRecord::priced(today, "claude-sonnet-5", usage(10, 1)))
            .collect();
        let mut ledger = SpendLedger::of(&records);
        assert_eq!(ledger.items_on(today), 199);
        assert_eq!(ledger.refused(today, 0, &caps), None);
        assert_eq!(ledger.refused(today, 1, &caps), Some(JudgementCap::Day));
        ledger.add(&records[0]);
        assert_eq!(ledger.refused(today, 0, &caps), Some(JudgementCap::Day));
        assert_eq!(ledger.refused(LocalDate::new(2026, 10, 17), 0, &caps), None);
    }

    /// Usage that adds up to five dollars stops the month; the next month
    /// starts again from nothing.
    #[test]
    fn the_month_cap_counts_money_per_calendar_month() {
        let caps = CloudCaps::default();
        let ledger = SpendLedger::of(&[
            SpendRecord::priced(
                LocalDate::new(2026, 10, 1),
                "claude-sonnet-5",
                usage(1_000_000, 0),
            ),
            SpendRecord::priced(
                LocalDate::new(2026, 10, 31),
                "claude-sonnet-5",
                usage(500_000, 0),
            ),
        ]);
        let late = LocalDate::new(2026, 10, 31);
        assert_eq!(ledger.spent_in_month_of(late), 3_000_000);
        assert_eq!(ledger.refused(late, 0, &caps), None);
        let more = SpendLedger::of(&[
            SpendRecord::priced(late, "claude-sonnet-5", usage(1_000_000, 0)),
            SpendRecord::priced(late, "claude-sonnet-5", usage(500_000, 0)),
            SpendRecord::priced(
                LocalDate::new(2026, 10, 2),
                "claude-sonnet-5",
                usage(1_000_000, 0),
            ),
        ]);
        assert_eq!(more.spent_in_month_of(late), 5_000_000);
        assert_eq!(more.refused(late, 0, &caps), Some(JudgementCap::Month));
        assert_eq!(more.refused(LocalDate::new(2026, 11, 1), 0, &caps), None);
        assert_eq!(more.refused(LocalDate::new(2025, 10, 31), 0, &caps), None);
    }

    #[test]
    fn the_cap_notice_names_the_waiting_items() {
        let notice = CapNotice {
            cap: JudgementCap::Day,
            waiting: 7,
        };
        assert_eq!(
            notice.line(),
            "The AI check reached its limit for this scan. 7 items will be looked at next time."
        );
        let one = CapNotice {
            cap: JudgementCap::Scan,
            waiting: 1,
        };
        assert_eq!(
            one.line(),
            "The AI check reached its limit for this scan. 1 item will be looked at next time."
        );
        for cap in [JudgementCap::Scan, JudgementCap::Day, JudgementCap::Month] {
            assert_eq!(JudgementCap::parse(cap.as_str()), Some(cap));
        }
    }
}
