use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// KRBTGT account information and security status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KrbtgtAccountInfo {
    pub distinguished_name: String,
    pub sam_account_name: String,
    pub domain: String,
    pub created: String,
    pub last_password_change: String,
    pub password_age_days: i64,
    pub account_status: AccountStatus,
    pub key_version_number: u32,
    pub last_rotation_info: Option<RotationInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStatus {
    pub is_enabled: bool,
    pub is_locked: bool,
    pub password_never_expires: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationInfo {
    pub first_rotation_time: Option<String>,
    pub second_rotation_time: Option<String>,
    pub rotation_complete: bool,
    pub performed_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KrbtgtAgeAnalysis {
    pub account_info: KrbtgtAccountInfo,
    pub age_days: i64,
    pub recommended_max_age_days: i64,
    pub is_overdue: bool,
    pub risk_level: KrbtgtRiskLevel,
    pub age_status: AgeStatus,
    pub recommendations: Vec<KrbtgtRecommendation>,
    pub analysis_timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KrbtgtRiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Healthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgeStatus {
    Healthy,
    Approaching,
    Overdue,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KrbtgtRecommendation {
    pub priority: KrbtgtRiskLevel,
    pub title: String,
    pub description: String,
    pub action_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRequest {
    pub rotation_number: u8, // 1 or 2
    pub confirm_understanding: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationResult {
    pub success: bool,
    pub rotation_number: u8,
    pub new_key_version: u32,
    pub timestamp: String,
    pub message: String,
    pub next_steps: Vec<String>,
    pub wait_time_recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RotationStatus {
    pub rotation_in_progress: bool,
    pub first_rotation_complete: bool,
    pub second_rotation_complete: bool,
    pub first_rotation_time: Option<String>,
    pub second_rotation_time: Option<String>,
    pub time_since_first_rotation: Option<i64>,
    pub ready_for_second_rotation: bool,
    pub minimum_wait_hours: i64,
    pub recommended_wait_hours: i64,
}

// Constants for KRBTGT management
const RECOMMENDED_MAX_AGE_DAYS: i64 = 180; // 6 months
const WARNING_THRESHOLD_DAYS: i64 = 150;
const CRITICAL_THRESHOLD_DAYS: i64 = 365;
const MINIMUM_ROTATION_WAIT_HOURS: i64 = 10; // Minimum TGT lifetime
const RECOMMENDED_ROTATION_WAIT_HOURS: i64 = 24;

pub fn analyze_krbtgt_age(account_info: &KrbtgtAccountInfo) -> KrbtgtAgeAnalysis {
    let age_days = account_info.password_age_days;
    
    let (risk_level, age_status) = if age_days > CRITICAL_THRESHOLD_DAYS {
        (KrbtgtRiskLevel::Critical, AgeStatus::Critical)
    } else if age_days > RECOMMENDED_MAX_AGE_DAYS {
        (KrbtgtRiskLevel::High, AgeStatus::Overdue)
    } else if age_days > WARNING_THRESHOLD_DAYS {
        (KrbtgtRiskLevel::Medium, AgeStatus::Approaching)
    } else if age_days > 90 {
        (KrbtgtRiskLevel::Low, AgeStatus::Healthy)
    } else {
        (KrbtgtRiskLevel::Healthy, AgeStatus::Healthy)
    };

    let is_overdue = age_days > RECOMMENDED_MAX_AGE_DAYS;
    let mut recommendations = Vec::new();

    match age_status {
        AgeStatus::Critical => {
            recommendations.push(KrbtgtRecommendation {
                priority: KrbtgtRiskLevel::Critical,
                title: "Immediate KRBTGT Rotation Required".to_string(),
                description: format!(
                    "The KRBTGT password is {} days old, exceeding the critical threshold of {} days. \
                    This significantly increases the risk of Golden Ticket attacks if credentials are compromised.",
                    age_days, CRITICAL_THRESHOLD_DAYS
                ),
                action_required: true,
            });
            recommendations.push(KrbtgtRecommendation {
                priority: KrbtgtRiskLevel::High,
                title: "Review Security Logs".to_string(),
                description: "Before rotation, review security logs for signs of compromise or unauthorized Kerberos ticket activity.".to_string(),
                action_required: true,
            });
        }
        AgeStatus::Overdue => {
            recommendations.push(KrbtgtRecommendation {
                priority: KrbtgtRiskLevel::High,
                title: "KRBTGT Rotation Recommended".to_string(),
                description: format!(
                    "The KRBTGT password is {} days old, exceeding the recommended maximum of {} days. \
                    Schedule a rotation during a maintenance window.",
                    age_days, RECOMMENDED_MAX_AGE_DAYS
                ),
                action_required: true,
            });
        }
        AgeStatus::Approaching => {
            recommendations.push(KrbtgtRecommendation {
                priority: KrbtgtRiskLevel::Medium,
                title: "Plan KRBTGT Rotation".to_string(),
                description: format!(
                    "The KRBTGT password will exceed the recommended age in {} days. Begin planning the rotation process.",
                    RECOMMENDED_MAX_AGE_DAYS - age_days
                ),
                action_required: false,
            });
        }
        AgeStatus::Healthy => {
            recommendations.push(KrbtgtRecommendation {
                priority: KrbtgtRiskLevel::Healthy,
                title: "KRBTGT Age Within Acceptable Range".to_string(),
                description: format!(
                    "The KRBTGT password was last changed {} days ago. Next rotation recommended in approximately {} days.",
                    age_days, RECOMMENDED_MAX_AGE_DAYS - age_days
                ),
                action_required: false,
            });
        }
    }

    // Always add education recommendation
    recommendations.push(KrbtgtRecommendation {
        priority: KrbtgtRiskLevel::Low,
        title: "Remember: Two Rotations Required".to_string(),
        description: "KRBTGT rotation must be performed twice to fully invalidate existing tickets. \
            Wait at least 10 hours (maximum TGT lifetime) between rotations.".to_string(),
        action_required: false,
    });

    KrbtgtAgeAnalysis {
        account_info: account_info.clone(),
        age_days,
        recommended_max_age_days: RECOMMENDED_MAX_AGE_DAYS,
        is_overdue,
        risk_level,
        age_status,
        recommendations,
        analysis_timestamp: Utc::now().to_rfc3339(),
    }
}

pub fn calculate_rotation_status(rotation_info: &Option<RotationInfo>) -> RotationStatus {
    match rotation_info {
        Some(info) => {
            let first_complete = info.first_rotation_time.is_some();
            let second_complete = info.second_rotation_time.is_some();
            
            let time_since_first = if let Some(first_time) = &info.first_rotation_time {
                if let Ok(dt) = DateTime::parse_from_rfc3339(first_time) {
                    let duration = Utc::now().signed_duration_since(dt.with_timezone(&Utc));
                    Some(duration.num_hours())
                } else {
                    None
                }
            } else {
                None
            };

            let ready_for_second = time_since_first
                .map(|hours| hours >= MINIMUM_ROTATION_WAIT_HOURS)
                .unwrap_or(false);

            RotationStatus {
                rotation_in_progress: first_complete && !second_complete,
                first_rotation_complete: first_complete,
                second_rotation_complete: second_complete,
                first_rotation_time: info.first_rotation_time.clone(),
                second_rotation_time: info.second_rotation_time.clone(),
                time_since_first_rotation: time_since_first,
                ready_for_second_rotation: ready_for_second,
                minimum_wait_hours: MINIMUM_ROTATION_WAIT_HOURS,
                recommended_wait_hours: RECOMMENDED_ROTATION_WAIT_HOURS,
            }
        }
        None => RotationStatus {
            rotation_in_progress: false,
            first_rotation_complete: false,
            second_rotation_complete: false,
            first_rotation_time: None,
            second_rotation_time: None,
            time_since_first_rotation: None,
            ready_for_second_rotation: false,
            minimum_wait_hours: MINIMUM_ROTATION_WAIT_HOURS,
            recommended_wait_hours: RECOMMENDED_ROTATION_WAIT_HOURS,
        },
    }
}

pub fn validate_rotation_request(
    request: &RotationRequest,
    current_status: &RotationStatus,
) -> Result<()> {
    if !request.confirm_understanding {
        return Err(anyhow!(
            "You must confirm understanding of the rotation implications before proceeding"
        ));
    }

    if request.reason.trim().is_empty() {
        return Err(anyhow!("A reason for the rotation must be provided for audit purposes"));
    }

    match request.rotation_number {
        1 => {
            if current_status.first_rotation_complete && !current_status.second_rotation_complete {
                return Err(anyhow!(
                    "First rotation already complete. Please complete the second rotation."
                ));
            }
        }
        2 => {
            if !current_status.first_rotation_complete {
                return Err(anyhow!(
                    "First rotation must be completed before second rotation"
                ));
            }
            if current_status.second_rotation_complete {
                return Err(anyhow!(
                    "Both rotations already complete. Start a new rotation cycle."
                ));
            }
            if !current_status.ready_for_second_rotation {
                let remaining = current_status.minimum_wait_hours
                    - current_status.time_since_first_rotation.unwrap_or(0);
                return Err(anyhow!(
                    "Not enough time has passed since first rotation. Please wait {} more hours.",
                    remaining
                ));
            }
        }
        _ => {
            return Err(anyhow!("Invalid rotation number. Must be 1 or 2."));
        }
    }

    Ok(())
}

impl std::fmt::Display for KrbtgtRiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KrbtgtRiskLevel::Critical => write!(f, "Critical"),
            KrbtgtRiskLevel::High => write!(f, "High"),
            KrbtgtRiskLevel::Medium => write!(f, "Medium"),
            KrbtgtRiskLevel::Low => write!(f, "Low"),
            KrbtgtRiskLevel::Healthy => write!(f, "Healthy"),
        }
    }
}
