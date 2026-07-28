//! Distributed tracing for request flow tracking.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// A span in a distributed trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub operation_name: String,
    pub start_time: String,
    pub end_time: Option<String>,
    pub duration_ms: Option<f64>,
    pub tags: HashMap<String, String>,
    pub status: SpanStatus,
}

/// Span status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpanStatus {
    Ok,
    Error,
    Canceled,
}

/// Tracer for distributed tracing.
#[derive(Debug, Default)]
pub struct Tracer {
    pub spans: Vec<TraceSpan>,
}

impl Tracer {
    pub fn new() -> Self {
        Self { spans: Vec::new() }
    }

    /// Start a new trace span.
    pub fn start_span(&mut self, operation: &str, trace_id: &str, parent_span_id: Option<&str>) -> String {
        let span_id = uuid::Uuid::new_v4().to_string();
        self.spans.push(TraceSpan {
            trace_id: trace_id.to_string(),
            span_id: span_id.clone(),
            parent_span_id: parent_span_id.map(|s| s.to_string()),
            operation_name: operation.to_string(),
            start_time: chrono::Utc::now().to_rfc3339(),
            end_time: None,
            duration_ms: None,
            tags: HashMap::new(),
            status: SpanStatus::Ok,
        });
        span_id
    }

    /// End a span with a given duration.
    pub fn end_span(&mut self, span_id: &str, status: SpanStatus) {
        if let Some(span) = self.spans.iter_mut().find(|s| s.span_id == span_id) {
            span.end_time = Some(chrono::Utc::now().to_rfc3339());
            span.status = status;
        }
    }

    /// Add a tag to a span.
    pub fn add_tag(&mut self, span_id: &str, key: &str, value: &str) {
        if let Some(span) = self.spans.iter_mut().find(|s| s.span_id == span_id) {
            span.tags.insert(key.to_string(), value.to_string());
        }
    }

    /// Get all spans for a trace.
    pub fn trace_spans(&self, trace_id: &str) -> Vec<&TraceSpan> {
        self.spans.iter().filter(|s| s.trace_id == trace_id).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_lifecycle() {
        let mut tracer = Tracer::new();
        let trace_id = uuid::Uuid::new_v4().to_string();
        let span_id = tracer.start_span("operation", &trace_id, None);
        tracer.add_tag(&span_id, "key", "value");
        tracer.end_span(&span_id, SpanStatus::Ok);
        let spans = tracer.trace_spans(&trace_id);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].tags.get("key").unwrap(), "value");
    }
}
