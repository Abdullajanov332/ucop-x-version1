//! Timeline reconstruction for forensic analysis.

use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

/// A single timeline event.
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub source: String,
    pub description: String,
    pub confidence: f64,
}

/// Forensic timeline for event reconstruction.
#[derive(Debug, Default)]
pub struct Timeline {
    pub(crate) events: BTreeMap<DateTime<Utc>, Vec<TimelineEvent>>,
}

impl Timeline {
    pub fn new() -> Self {
        Self {
            events: BTreeMap::new(),
        }
    }

    /// Add an event to the timeline.
    pub fn add_event(&mut self, event: TimelineEvent) {
        self.events
            .entry(event.timestamp)
            .or_default()
            .push(event);
    }

    /// Get all events in chronological order.
    pub fn events(&self) -> Vec<&TimelineEvent> {
        self.events
            .values()
            .flat_map(|v| v.iter())
            .collect()
    }

    /// Get events within a time range.
    pub fn events_between(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<&TimelineEvent> {
        self.events
            .range(start..=end)
            .flat_map(|(_, v)| v.iter())
            .collect()
    }

    /// Filter events by type.
    pub fn filter_by_type(&self, event_type: &str) -> Vec<&TimelineEvent> {
        self.events()
            .into_iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }

    /// Get the time range of all events.
    pub fn time_range(&self) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
        let first = self.events.keys().next()?;
        let last = self.events.keys().next_back()?;
        Some((*first, *last))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeline_ordering() {
        let mut timeline = Timeline::new();
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(10);

        timeline.add_event(TimelineEvent {
            timestamp: t2,
            event_type: "late".into(),
            source: "test".into(),
            description: "Second event".into(),
            confidence: 1.0,
        });
        timeline.add_event(TimelineEvent {
            timestamp: t1,
            event_type: "early".into(),
            source: "test".into(),
            description: "First event".into(),
            confidence: 1.0,
        });

        let events = timeline.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].description, "First event");
        assert_eq!(events[1].description, "Second event");
    }

    #[test]
    fn test_filter_by_type() {
        let mut timeline = Timeline::new();
        let now = Utc::now();
        timeline.add_event(TimelineEvent {
            timestamp: now,
            event_type: "file-create".into(),
            source: "test".into(),
            description: "File created".into(),
            confidence: 0.9,
        });
        timeline.add_event(TimelineEvent {
            timestamp: now,
            event_type: "network".into(),
            source: "test".into(),
            description: "Connection".into(),
            confidence: 0.8,
        });
        assert_eq!(timeline.filter_by_type("file-create").len(), 1);
        assert_eq!(timeline.filter_by_type("network").len(), 1);
    }
}
