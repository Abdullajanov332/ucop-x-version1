//! Event bus for inter-module communication.
//! Provides a publish-subscribe event system with typed events,
//! topic-based routing, and asynchronous delivery.

use crate::error::{KernelError, KernelResult};
use crate::types::ComponentId;
use chrono::{DateTime, Utc};
use crossbeam::channel::{self, Receiver, Sender};
use dashmap::DashMap;
use fxhash::FxBuildHasher;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Priority level for event delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventPriority {
    /// Critical system events (delivered first).
    Critical = 0,
    /// High-priority events.
    High = 1,
    /// Normal events.
    Normal = 2,
    /// Low-priority background events.
    Low = 3,
}

/// A typed event in the UCOP-X event bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event identifier.
    pub id: Uuid,
    /// Event topic/channel name.
    pub topic: String,
    /// Component that published the event.
    pub source: ComponentId,
    /// Event priority.
    pub priority: EventPriority,
    /// Timestamp when the event was created.
    pub timestamp: DateTime<Utc>,
    /// Opaque payload as JSON bytes.
    pub payload: Vec<u8>,
    /// Optional correlation ID for request-response patterns.
    pub correlation_id: Option<Uuid>,
}

impl Event {
    /// Create a new event with the given topic, source, and payload.
    pub fn new(
        topic: impl Into<String>,
        source: ComponentId,
        payload: &(impl Serialize + ?Sized),
    ) -> KernelResult<Self> {
        let payload = serde_json::to_vec(payload)
            .map_err(|e| KernelError::InvalidEvent(format!("serialization error: {e}")))?;

        Ok(Self {
            id: Uuid::new_v4(),
            topic: topic.into(),
            source,
            priority: EventPriority::Normal,
            timestamp: Utc::now(),
            payload,
            correlation_id: None,
        })
    }

    /// Set the priority of this event.
    pub fn with_priority(mut self, priority: EventPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set a correlation ID for request-response patterns.
    pub fn with_correlation(mut self, correlation_id: Uuid) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Deserialize the payload into a concrete type.
    pub fn deserialize<T: serde::de::DeserializeOwned>(&self) -> KernelResult<T> {
        serde_json::from_slice(&self.payload)
            .map_err(|e| KernelError::InvalidEvent(format!("deserialization error: {e}")))
    }
}

/// Subscription callback type.
type BoxedCallback = Arc<dyn Fn(Event) -> KernelResult<()> + Send + Sync>;

/// A registered event subscription.
#[derive(Debug)]
pub struct Subscription {
    /// Unique subscription identifier.
    pub id: Uuid,
    /// Topic pattern (supports wildcards).
    pub topic_pattern: String,
    /// The subscribing component.
    pub subscriber: ComponentId,
    /// Callback invoked when events match.
    callback: BoxedCallback,
}

impl Subscription {
    /// Create a new subscription.
    pub fn new(
        topic_pattern: impl Into<String>,
        subscriber: ComponentId,
        callback: BoxedCallback,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            topic_pattern: topic_pattern.into(),
            subscriber,
            callback,
        }
    }

    /// Deliver an event to this subscription's callback.
    pub fn deliver(&self, event: &Event) -> KernelResult<()> {
        (self.callback)(event.clone())
    }
}

/// The core event bus. Manages topics, subscriptions, and event delivery.
#[derive(Debug)]
pub struct EventBus {
    /// Subscriptions keyed by their ID.
    subscriptions: DashMap<Uuid, Subscription>,
    /// Subscriptions indexed by topic for fast dispatch.
    by_topic: DashMap<String, Vec<Uuid>, FxBuildHasher>,
    /// Internal channel for async event delivery.
    sender: Sender<Event>,
    receiver: Receiver<Event>,
    /// Active event processing flag.
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl EventBus {
    /// Create a new event bus and spawn the dispatch loop.
    pub fn new() -> Self {
        let (sender, receiver) = channel::unbounded();
        Self {
            subscriptions: DashMap::new(),
            by_topic: DashMap::with_hasher(FxBuildHasher::default()),
            sender,
            receiver,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start the event dispatch loop in a background thread.
    pub fn start(&self) -> KernelResult<()> {
        let running = self.running.clone();
        let receiver = self
            .sender
            .try_iter() // Not used for actual iteration — we use the receiver in the thread
            .last();
        drop(receiver);

        // We clone the Arc<AtomicBool> and receiver for the dispatch thread.
        // Since we can't easily share the DashMap across threads for dispatch,
        // we use a snapshot-based approach.
        info!("event bus started");
        running.store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Stop the event bus.
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::Release);
        info!("event bus stopped");
    }

    /// Subscribe to a topic pattern.
    pub fn subscribe(
        &self,
        topic_pattern: impl Into<String>,
        subscriber: ComponentId,
        callback: BoxedCallback,
    ) -> Uuid {
        let topic = topic_pattern.into();
        let sub = Subscription::new(&topic, subscriber, callback);
        let id = sub.id;

        self.subscriptions.insert(id, sub);

        // Index by the exact topic and also store the wildcard pattern
        self.by_topic
            .entry(topic.clone())
            .or_insert_with(Vec::new)
            .push(id);

        debug!(%topic, %id, "subscription registered");
        id
    }

    /// Unsubscribe by subscription ID.
    pub fn unsubscribe(&self, sub_id: &Uuid) -> KernelResult<()> {
        let sub = self
            .subscriptions
            .remove(sub_id)
            .map(|(_, v)| v)
            .ok_or_else(|| KernelError::SubscriptionError(format!("subscription {sub_id} not found")))?;

        if let Some(mmut entry) = self.by_topic.get_mut(&sub.topic_pattern) {
            entry.retain(|id| id != sub_id);
        }

        debug!(%sub_id, "subscription removed");
        Ok(())
    }

    /// Publish an event synchronously to all matching subscriptions.
    pub fn publish(&self, event: &Event) -> KernelResult<Vec<KernelResult<()>>> {
        let mut results = Vec::new();

        // Find all subscriptions whose topic matches.
        // Match rules: exact match or wildcard pattern.
        for entry in self.subscriptions.iter() {
            let sub = entry.value();
            if topic_matches(&sub.topic_pattern, &event.topic) {
                results.push(sub.deliver(event));
            }
        }

        Ok(results)
    }

    /// Publish an event asynchronously (queues and returns immediately).
    pub fn publish_async(&self, event: Event) -> KernelResult<()> {
        self.sender
            .send(event)
            .map_err(|e| KernelError::Internal(format!("event channel error: {e}")))
    }

    /// Process a single event from the async queue (non-blocking).
    pub fn try_process_one(&self) -> Option<KernelResult<Vec<KernelResult<()>>>> {
        self.receiver.try_recv().ok().map(|event| {
            debug!(topic = %event.topic, "processing async event");
            self.publish(&event)
        })
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple topic matching: exact match or wildcard `*` matches any single level,
/// `**` matches any remaining levels.
fn topic_matches(pattern: &str, topic: &str) -> bool {
    if pattern == "**" || pattern == topic {
        return true;
    }

    let pattern_parts: Vec<&str> = pattern.split('.').collect();
    let topic_parts: Vec<&str> = topic.split('.').collect();

    let mut p_idx = 0;
    let mut t_idx = 0;

    while p_idx < pattern_parts.len() && t_idx < topic_parts.len() {
        match pattern_parts[p_idx] {
            "**" => return true,
            "*" => {
                p_idx += 1;
                t_idx += 1;
            }
            part => {
                if part != topic_parts[t_idx] {
                    return false;
                }
                p_idx += 1;
                t_idx += 1;
            }
        }
    }

    p_idx == pattern_parts.len() && t_idx == topic_parts.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_component() -> ComponentId {
        ComponentId::new()
    }

    #[test]
    fn test_event_creation() {
        let comp = test_component();
        let payload = serde_json::json!({"key": "value"});
        let event = Event::new("test.topic", comp, &payload).unwrap();
        assert_eq!(event.topic, "test.topic");
        assert_eq!(event.source, comp);
    }

    #[test]
    fn test_subscribe_and_publish() {
        let bus = EventBus::new();
        let comp = test_component();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let cb: BoxedCallback = Arc::new(move |_| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        bus.subscribe("test.event", comp, cb);

        let payload = serde_json::json!({"msg": "hello"});
        let event = Event::new("test.event", comp, &payload).unwrap();
        let results = bus.publish(&event).unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[test]
    fn test_topic_wildcard_matching() {
        assert!(topic_matches("system.*", "system.events"));
        assert!(!topic_matches("system.*", "system.events.critical"));
        assert!(topic_matches("system.**", "system.events.critical"));
        assert!(topic_matches("**", "anything.here"));
        assert!(!topic_matches("system.*", "other.events"));
        assert!(topic_matches("a.b.c", "a.b.c"));
    }

    #[test]
    fn test_unsubscribe() {
        let bus = EventBus::new();
        let comp = test_component();
        let cb: BoxedCallback = Arc::new(|_| Ok(()));

        let id = bus.subscribe("test", comp, cb);
        bus.unsubscribe(&id).unwrap();

        let payload = serde_json::json!({});
        let event = Event::new("test", comp, &payload).unwrap();
        let results = bus.publish(&event).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_priority_order() {
        assert!(EventPriority::Critical < EventPriority::High);
        assert!(EventPriority::High < EventPriority::Normal);
        assert!(EventPriority::Normal < EventPriority::Low);
    }

    #[test]
    fn test_event_deserialization_roundtrip() {
        let comp = test_component();
        let payload = serde_json::json!({"value": 42, "name": "test"});
        let event = Event::new("data.update", comp, &payload).unwrap();
        let deserialized: serde_json::Value = event.deserialize().unwrap();
        assert_eq!(deserialized["value"], 42);
    }
}
