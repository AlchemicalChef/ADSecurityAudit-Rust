use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentPriority {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentStatus {
    Open,
    Investigating,
    Contained,
    Resolved,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentAction {
    pub id: String,
    pub action_type: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub performed_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
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
    pub fn new(
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

    pub fn update_status(&mut self, status: IncidentStatus) {
        self.status = status;
        self.updated_at = Utc::now();
    }

    pub fn add_action(&mut self, action_type: String, description: String) {
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
