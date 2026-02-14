//! Security Incident Management Module
//!
//! Provides data structures and workflows for tracking and responding to
//! security incidents discovered during Active Directory audits.
//!
//! # Incident Lifecycle
//!
//! ```text
//! Open → Investigating → Contained → Resolved → Closed
//! ```
//!
//! # Priority Levels
//!
//! | Priority | Response Time | Description |
//! |----------|---------------|-------------|
//! | Critical | Immediate | Active attack, data breach, domain compromise |
//! | High | < 4 hours | Significant vulnerability, privileged account abuse |
//! | Medium | < 24 hours | Security misconfiguration, policy violation |
//! | Low | < 72 hours | Minor finding, informational |
//!
//! # Usage
//!
//! Incidents are automatically created when critical security findings are detected,
//! or can be manually created by security analysts during investigation.
//!
//! ```rust,ignore
//! let incident = Incident::new(
//!     "DCSync Rights Detected".to_string(),
//!     "Non-admin user has DCSync capability".to_string(),
//!     IncidentPriority::Critical,
//!     vec!["DC01.corp.local".to_string()],
//! );
//!
//! incident.add_action(
//!     "Containment".to_string(),
//!     "Removed DCSync ACE from user".to_string(),
//! );
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Priority classification for security incidents
///
/// Determines response urgency and escalation paths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum IncidentPriority {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum IncidentStatus {
    Open,
    Investigating,
    Contained,
    Resolved,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IncidentAction {
    pub id: String,
    pub action_type: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub performed_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Incident {
    pub id: String,
    pub title: String,
    pub description: String,
    pub priority: IncidentPriority,
    pub status: IncidentStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub affected_systems: Vec<String>,
    pub actions: Vec<IncidentAction>,
    pub assigned_to: Option<String>,
}

impl Incident {
    pub(crate) fn new(
        title: String,
        description: String,
        priority: IncidentPriority,
        affected_systems: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            title,
            description,
            priority,
            status: IncidentStatus::Open,
            created_at: now,
            updated_at: now,
            affected_systems,
            actions: Vec::new(),
            assigned_to: None,
        }
    }

    pub(crate) fn update_status(&mut self, status: IncidentStatus) {
        self.status = status;
        self.updated_at = Utc::now();
    }

    pub(crate) fn add_action(&mut self, action_type: String, description: String) {
        let action = IncidentAction {
            id: Uuid::new_v4().to_string(),
            action_type,
            description,
            timestamp: Utc::now(),
            performed_by: "System".to_string(), // In production, use actual user
        };
        self.actions.push(action);
        self.updated_at = Utc::now();
    }
}
