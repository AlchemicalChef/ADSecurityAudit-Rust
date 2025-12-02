//! Anomaly Detection for Active Directory Changes
//!
//! Machine learning-inspired behavioral analytics to detect:
//! - Unusual privilege escalations
//! - Abnormal access patterns
//! - Suspicious group membership changes
//! - Anomalous authentication behavior
//!
// Allow unused code - advanced detection methods for future features
#![allow(dead_code)]

use chrono::{DateTime, Utc, Duration, Datelike, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Anomaly severity classification for prioritizing security alerts
///
/// Determines urgency of response required for detected anomalies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnomalySeverity {
    /// Low severity - informational, routine monitoring
    Low,
    /// Medium severity - unusual activity requiring investigation
    Medium,
    /// High severity - suspicious activity requiring prompt attention
    High,
    /// Critical severity - likely security incident, immediate action required
    Critical,
}

/// Types of anomalies detected by the behavioral analytics engine
///
/// Each type represents a specific security concern with different
/// detection algorithms and baseline comparisons.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AnomalyType {
    /// Logon occurring outside typical hours for the entity
    UnusualLogonTime,
    /// Logon from atypical IP address or location
    UnusualLogonLocation,
    /// User added to privileged groups
    PrivilegeEscalation,
    /// Large number of group membership changes in short time
    MassGroupChange,
    /// Excessive logon attempts in short time window (credential stuffing)
    RapidFireLogons,
    /// Unusual LDAP query patterns
    SuspiciousQuery,
    /// Unexpected AD configuration changes
    ConfigurationChange,
    /// User account creation with suspicious attributes
    UnusualUserCreation,
    /// Multiple failed authentication attempts
    BruteForceAttempt,
    /// Indicators of lateral movement across systems
    LateralMovement,
}

/// Detected anomaly with supporting evidence and recommended actions
///
/// Represents a single detected security anomaly with all relevant
/// context for investigation and response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Unique identifier for this anomaly (UUID)
    pub id: String,
    /// Timestamp when anomaly was detected
    pub detected_at: DateTime<Utc>,
    /// Type/category of the anomaly
    pub anomaly_type: AnomalyType,
    /// Severity level for prioritization
    pub severity: AnomalySeverity,
    /// Confidence score (0.0-1.0) in the detection
    pub confidence: f64,
    /// Entity that triggered the anomaly (username, group, etc.)
    pub subject: String,
    /// Human-readable description of the anomaly
    pub description: String,
    /// Supporting evidence for the anomaly detection
    pub evidence: Vec<String>,
    /// Description of expected baseline behavior
    pub baseline: Option<String>,
    /// Numeric deviation from baseline (higher = more anomalous)
    pub deviation: f64,
    /// Prioritized list of recommended response actions
    pub recommended_actions: Vec<String>,
}

/// Learned behavioral baseline for an entity
///
/// Machine learning-inspired profile that captures normal behavior patterns
/// for anomaly detection. Built from historical activity analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralBaseline {
    /// Entity identifier (username, computer name, etc.)
    pub entity: String,
    /// Type of entity this baseline represents
    pub entity_type: EntityType,
    /// When this baseline was initially created
    pub created_at: DateTime<Utc>,
    /// When this baseline was last updated
    pub updated_at: DateTime<Utc>,
    /// Hours of day (0-23) when this entity typically logs on
    pub typical_logon_hours: Vec<u8>,
    /// Days of week (0-6, Monday=0) when this entity typically logs on
    pub typical_logon_days: Vec<u8>,
    /// Average number of logon sessions per day
    pub average_sessions_per_day: f64,
    /// IP addresses commonly used by this entity
    pub typical_source_ips: Vec<String>,
    /// Group memberships for detecting privilege changes
    pub group_memberships: Vec<String>,
    /// Whether this entity has privileged access
    pub privileged: bool,
    /// Threshold for failed logon anomaly detection
    pub failed_logon_threshold: u32,
}

/// Type of entity being monitored for anomalies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EntityType {
    /// User account
    User,
    /// Computer/device account
    Computer,
    /// Security or distribution group
    Group,
    /// Service account (higher scrutiny for anomalies)
    ServiceAccount,
}

/// Anomaly detection engine
pub struct AnomalyDetector {
    baselines: HashMap<String, BehavioralBaseline>,
    detection_sensitivity: f64,  // 0.0 to 1.0, higher = more sensitive
}

impl AnomalyDetector {
    /// Creates a new anomaly detection engine with specified sensitivity
    ///
    /// # Arguments
    /// * `sensitivity` - Detection sensitivity (0.0-1.0)
    ///   - 0.0: Low sensitivity, fewer false positives, may miss subtle anomalies
    ///   - 1.0: High sensitivity, catches more anomalies, more false positives
    ///   - Recommended: 0.7 for balanced detection
    ///
    /// # Returns
    /// New AnomalyDetector instance with empty baseline set
    ///
    /// # Examples
    /// ```
    /// let detector = AnomalyDetector::new(0.7);  // Balanced sensitivity
    /// ```
    pub fn new(sensitivity: f64) -> Self {
        Self {
            baselines: HashMap::new(),
            detection_sensitivity: sensitivity.clamp(0.0, 1.0),
        }
    }

    /// Builds behavioral baseline by learning from historical logon patterns
    ///
    /// Analyzes historical logon events to learn normal behavior patterns including:
    /// - Typical hours of activity
    /// - Typical days of the week
    /// - Common source IP addresses
    /// - Average session frequency
    ///
    /// # Arguments
    /// * `entity` - Entity identifier (username, computer name, etc.)
    /// * `entity_type` - Type of entity (User, Computer, ServiceAccount, Group)
    /// * `logon_history` - Historical logon events for analysis (minimum 10 recommended)
    ///
    /// # Algorithm
    /// 1. Analyze timestamp patterns to extract hours and days
    /// 2. Count frequency of each hour/day/IP
    /// 3. Filter to patterns appearing in >10% of events (typical behavior)
    /// 4. Calculate average sessions per day over the observation period
    /// 5. Store baseline for future anomaly comparisons
    ///
    /// # Examples
    /// ```
    /// let mut detector = AnomalyDetector::new(0.7);
    /// let history = vec![
    ///     LogonEvent { timestamp: Utc::now(), username: "jdoe".to_string(), ... },
    ///     // ... more historical events
    /// ];
    /// detector.build_baseline("jdoe".to_string(), EntityType::User, &history);
    /// // Baseline is now ready for anomaly detection
    /// ```
    pub fn build_baseline(
        &mut self,
        entity: String,
        entity_type: EntityType,
        logon_history: &[LogonEvent],
    ) {
        let mut typical_hours = HashMap::new();
        let mut typical_days = HashMap::new();
        let mut source_ips = HashMap::new();

        for event in logon_history {
            let hour = event.timestamp.time().hour() as u8;
            let day_of_week = event.timestamp.weekday().num_days_from_monday() as u8;

            *typical_hours.entry(hour).or_insert(0u32) += 1;
            *typical_days.entry(day_of_week).or_insert(0u32) += 1;

            if let Some(ip) = &event.source_ip {
                *source_ips.entry(ip.clone()).or_insert(0u32) += 1;
            }
        }

        // Extract most common hours (>10% of activity)
        let total_events = logon_history.len() as f64;
        let mut typical_logon_hours: Vec<u8> = typical_hours
            .into_iter()
            .filter(|(_, count)| (*count as f64 / total_events) > 0.10)
            .map(|(hour, _)| hour)
            .collect();
        typical_logon_hours.sort();

        // Extract most common days
        let mut typical_logon_days: Vec<u8> = typical_days
            .into_iter()
            .filter(|(_, count)| (*count as f64 / total_events) > 0.10)
            .map(|(day, _)| day)
            .collect();
        typical_logon_days.sort();

        // Extract common source IPs
        let typical_source_ips: Vec<String> = source_ips
            .into_iter()
            .filter(|(_, count)| (*count as f64 / total_events) > 0.05)
            .map(|(ip, _)| ip)
            .collect();

        // Calculate average sessions per day
        let date_range = if let (Some(first), Some(last)) = (logon_history.first(), logon_history.last()) {
            last.timestamp.signed_duration_since(first.timestamp).num_days().max(1) as f64
        } else {
            1.0
        };
        let average_sessions_per_day = total_events / date_range;

        let baseline = BehavioralBaseline {
            entity: entity.clone(),
            entity_type,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            typical_logon_hours,
            typical_logon_days,
            average_sessions_per_day,
            typical_source_ips,
            group_memberships: Vec::new(),
            privileged: false,
            failed_logon_threshold: 5,
        };

        self.baselines.insert(entity, baseline);
    }

    /// Detects anomalies in a logon event by comparing to baseline behavior
    ///
    /// Checks for two primary anomaly types:
    /// 1. **UnusualLogonTime** - Logon outside typical hours
    /// 2. **UnusualLogonLocation** - Logon from atypical IP address
    ///
    /// # Arguments
    /// * `entity` - Entity identifier to check (must have existing baseline)
    /// * `event` - Logon event to analyze
    ///
    /// # Returns
    /// Vector of detected anomalies (empty if behavior is normal)
    ///
    /// # Algorithm
    /// 1. Retrieve baseline for the entity
    /// 2. Extract hour and IP from logon event
    /// 3. Compare hour against typical_logon_hours
    /// 4. Compare IP against typical_source_ips
    /// 5. Generate anomaly records for deviations
    /// 6. Adjust severity based on privileged status
    /// 7. Calculate confidence score using detection sensitivity
    ///
    /// # Examples
    /// ```
    /// let anomalies = detector.detect_logon_anomalies("jdoe", &logon_event);
    /// if !anomalies.is_empty() {
    ///     for anomaly in anomalies {
    ///         println!("Detected: {} (confidence: {})", anomaly.description, anomaly.confidence);
    ///     }
    /// }
    /// ```
    pub fn detect_logon_anomalies(
        &self,
        entity: &str,
        event: &LogonEvent,
    ) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        if let Some(baseline) = self.baselines.get(entity) {
            let hour = event.timestamp.time().hour() as u8;
            let _day = event.timestamp.weekday().num_days_from_monday() as u8;  // Reserved for day-of-week anomaly detection

            // Check for unusual time
            if !baseline.typical_logon_hours.contains(&hour) {
                let confidence = 0.7 + (self.detection_sensitivity * 0.3);
                anomalies.push(Anomaly {
                    id: uuid::Uuid::new_v4().to_string(),
                    detected_at: Utc::now(),
                    anomaly_type: AnomalyType::UnusualLogonTime,
                    severity: if baseline.privileged {
                        AnomalySeverity::High
                    } else {
                        AnomalySeverity::Medium
                    },
                    confidence,
                    subject: entity.to_string(),
                    description: format!(
                        "Logon at unusual time: {}:00 (typical hours: {:?})",
                        hour, baseline.typical_logon_hours
                    ),
                    evidence: vec![
                        format!("Logon time: {}", event.timestamp.format("%Y-%m-%d %H:%M:%S")),
                        format!("Typical hours: {:?}", baseline.typical_logon_hours),
                    ],
                    baseline: Some(format!("Typical hours: {:?}", baseline.typical_logon_hours)),
                    deviation: 1.0,
                    recommended_actions: vec![
                        "Verify with user if this logon was authorized".to_string(),
                        "Check for compromised credentials".to_string(),
                    ],
                });
            }

            // Check for unusual location (IP address)
            if let Some(source_ip) = &event.source_ip {
                if !baseline.typical_source_ips.is_empty() && !baseline.typical_source_ips.contains(source_ip) {
                    let confidence = 0.65 + (self.detection_sensitivity * 0.35);
                    anomalies.push(Anomaly {
                        id: uuid::Uuid::new_v4().to_string(),
                        detected_at: Utc::now(),
                        anomaly_type: AnomalyType::UnusualLogonLocation,
                        severity: if baseline.privileged {
                            AnomalySeverity::Critical
                        } else {
                            AnomalySeverity::Medium
                        },
                        confidence,
                        subject: entity.to_string(),
                        description: format!(
                            "Logon from unusual location: {} (typical IPs: {:?})",
                            source_ip, baseline.typical_source_ips
                        ),
                        evidence: vec![
                            format!("Source IP: {}", source_ip),
                            format!("Typical IPs: {:?}", baseline.typical_source_ips),
                        ],
                        baseline: Some(format!("Typical IPs: {:?}", baseline.typical_source_ips)),
                        deviation: 1.0,
                        recommended_actions: vec![
                            "Immediately verify this logon with the user".to_string(),
                            "Consider blocking source IP if unauthorized".to_string(),
                            "Check for account compromise".to_string(),
                        ],
                    });
                }
            }
        }

        anomalies
    }

    /// Detects rapid-fire logon attempts indicating credential stuffing or brute force
    ///
    /// Identifies excessive logon attempts in a short time window, which may indicate:
    /// - Credential stuffing attack
    /// - Brute force attempt
    /// - Compromised credentials being tested
    ///
    /// # Arguments
    /// * `entity` - Entity identifier to check
    /// * `recent_logons` - Recent logon events within observation window
    /// * `time_window_minutes` - Size of time window to analyze
    ///
    /// # Returns
    /// Some(Anomaly) if rapid-fire pattern detected, None otherwise
    ///
    /// # Algorithm
    /// 1. Filter events to those within the time window
    /// 2. Check if count exceeds threshold (≥10 logons)
    /// 3. Compare to baseline average rate
    /// 4. Calculate deviation ratio (actual / expected rate)
    /// 5. If deviation >5x normal, generate Critical anomaly
    /// 6. Include comprehensive evidence and recommended actions
    ///
    /// # Detection Thresholds
    /// - Minimum events: 10 logons
    /// - Minimum deviation: 5x baseline rate
    /// - Severity: Always Critical
    /// - Confidence: 0.9 (very high)
    ///
    /// # Examples
    /// ```
    /// let anomaly = detector.detect_rapid_logons(
    ///     "jdoe",
    ///     &recent_events,
    ///     15  // 15-minute window
    /// );
    /// if let Some(a) = anomaly {
    ///     println!("CRITICAL: Possible credential stuffing attack!");
    ///     println!("Recommended: Disable account immediately");
    /// }
    /// ```
    pub fn detect_rapid_logons(
        &self,
        entity: &str,
        recent_logons: &[LogonEvent],
        time_window_minutes: i64,
    ) -> Option<Anomaly> {
        if recent_logons.len() < 3 {
            return None;
        }

        let now = Utc::now();
        let threshold = now - Duration::minutes(time_window_minutes);

        let rapid_logons: Vec<&LogonEvent> = recent_logons
            .iter()
            .filter(|e| e.timestamp > threshold)
            .collect();

        if rapid_logons.len() >= 10 {
            let baseline = self.baselines.get(entity);
            let expected_rate = baseline.map(|b| b.average_sessions_per_day / 24.0 / 60.0).unwrap_or(0.1);
            let actual_rate = rapid_logons.len() as f64 / time_window_minutes as f64;
            let deviation = actual_rate / expected_rate.max(0.01);

            if deviation > 5.0 {
                return Some(Anomaly {
                    id: uuid::Uuid::new_v4().to_string(),
                    detected_at: Utc::now(),
                    anomaly_type: AnomalyType::RapidFireLogons,
                    severity: AnomalySeverity::Critical,
                    confidence: 0.9,
                    subject: entity.to_string(),
                    description: format!(
                        "Detected {} logon attempts in {} minutes ({}x normal rate)",
                        rapid_logons.len(), time_window_minutes, deviation as i32
                    ),
                    evidence: vec![
                        format!("Logon count: {}", rapid_logons.len()),
                        format!("Time window: {} minutes", time_window_minutes),
                        format!("Deviation from baseline: {}x", deviation as i32),
                    ],
                    baseline: baseline.map(|b| format!("Average rate: {:.2}/min", b.average_sessions_per_day / 24.0 / 60.0)),
                    deviation,
                    recommended_actions: vec![
                        "Immediately disable the account".to_string(),
                        "Investigate for credential stuffing or brute force attack".to_string(),
                        "Check source IPs and geolocation".to_string(),
                        "Force password reset after verification".to_string(),
                    ],
                });
            }
        }

        None
    }

    /// Detects privilege escalation by monitoring group membership changes
    ///
    /// Identifies when a user is added to privileged groups, which may indicate:
    /// - Unauthorized privilege escalation
    /// - Compromised administrator credentials
    /// - Insider threat activity
    ///
    /// # Arguments
    /// * `entity` - Entity identifier (username)
    /// * `old_groups` - Previous group memberships
    /// * `new_groups` - Current group memberships
    ///
    /// # Returns
    /// Vector of anomalies (one per privileged group addition)
    ///
    /// # Algorithm
    /// 1. Define list of privileged groups to monitor
    /// 2. Filter old/new groups to only privileged ones
    /// 3. Identify newly added privileged groups
    /// 4. For each addition, generate Critical anomaly
    /// 5. Set confidence to 1.0 (absolute certainty of change)
    /// 6. Provide detailed evidence and response actions
    ///
    /// # Monitored Privileged Groups
    /// - Domain Admins
    /// - Enterprise Admins
    /// - Schema Admins
    /// - Administrators
    /// - Account Operators
    /// - Backup Operators
    /// - Server Operators
    /// - Print Operators
    ///
    /// # Examples
    /// ```
    /// let old = vec!["Users".to_string()];
    /// let new = vec!["Users".to_string(), "Domain Admins".to_string()];
    /// let anomalies = detector.detect_privilege_escalation("jdoe", &old, &new);
    /// // Returns 1 Critical anomaly for Domain Admins addition
    /// ```
    pub fn detect_privilege_escalation(
        &self,
        entity: &str,
        old_groups: &[String],
        new_groups: &[String],
    ) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        let privileged_groups = [
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Print Operators",
        ];

        let old_privileged: Vec<&String> = old_groups
            .iter()
            .filter(|g| privileged_groups.iter().any(|pg| g.contains(pg)))
            .collect();

        let new_privileged: Vec<&String> = new_groups
            .iter()
            .filter(|g| privileged_groups.iter().any(|pg| g.contains(pg)))
            .collect();

        if new_privileged.len() > old_privileged.len() {
            let added_groups: Vec<String> = new_privileged
                .iter()
                .filter(|g| !old_privileged.contains(g))
                .map(|g| g.to_string())
                .collect();

            if !added_groups.is_empty() {
                anomalies.push(Anomaly {
                    id: uuid::Uuid::new_v4().to_string(),
                    detected_at: Utc::now(),
                    anomaly_type: AnomalyType::PrivilegeEscalation,
                    severity: AnomalySeverity::Critical,
                    confidence: 1.0,
                    subject: entity.to_string(),
                    description: format!(
                        "User added to privileged group(s): {}",
                        added_groups.join(", ")
                    ),
                    evidence: vec![
                        format!("Added to groups: {}", added_groups.join(", ")),
                        format!("Previous privileged groups: {}", old_privileged.len()),
                        format!("New privileged groups: {}", new_privileged.len()),
                    ],
                    baseline: Some(format!("Previous groups: {:?}", old_privileged)),
                    deviation: (new_privileged.len() - old_privileged.len()) as f64,
                    recommended_actions: vec![
                        "Immediately verify this change was authorized".to_string(),
                        "Review change logs and audit trail".to_string(),
                        "If unauthorized, remove user from privileged groups".to_string(),
                        "Check for account compromise".to_string(),
                    ],
                });
            }
        }

        anomalies
    }

    /// Detects mass group membership changes indicating possible attack or misconfiguration
    ///
    /// Identifies bulk changes to group membership, which may indicate:
    /// - Mass privilege escalation attack
    /// - Scripted attack or malware
    /// - Misconfigured automation or accidental bulk operation
    ///
    /// # Arguments
    /// * `group_name` - Name of the group being modified
    /// * `members_added` - Number of members added
    /// * `members_removed` - Number of members removed
    /// * `time_window_minutes` - Time window for the changes
    ///
    /// # Returns
    /// Some(Anomaly) if mass change pattern detected, None otherwise
    ///
    /// # Algorithm
    /// 1. Calculate total changes (additions + removals)
    /// 2. Check if total >10 changes in <30 minutes
    /// 3. If threshold exceeded, generate anomaly
    /// 4. Set severity to Critical if group contains "Admin", otherwise High
    /// 5. Provide evidence and recommended verification steps
    ///
    /// # Detection Thresholds
    /// - Minimum changes: >10 total changes
    /// - Maximum time window: <30 minutes
    /// - Severity: Critical (admin groups) or High (other groups)
    /// - Confidence: 0.85
    ///
    /// # Examples
    /// ```
    /// let anomaly = detector.detect_mass_group_changes(
    ///     "Domain Admins",
    ///     15,  // 15 members added
    ///     0,   // 0 removed
    ///     10   // in 10 minutes
    /// );
    /// // Returns Critical anomaly - possible mass privilege escalation
    /// ```
    pub fn detect_mass_group_changes(
        &self,
        group_name: &str,
        members_added: usize,
        members_removed: usize,
        time_window_minutes: i64,
    ) -> Option<Anomaly> {
        let total_changes = members_added + members_removed;

        // Threshold: more than 10 changes in short time window
        if total_changes > 10 && time_window_minutes < 30 {
            return Some(Anomaly {
                id: uuid::Uuid::new_v4().to_string(),
                detected_at: Utc::now(),
                anomaly_type: AnomalyType::MassGroupChange,
                severity: if group_name.contains("Admin") {
                    AnomalySeverity::Critical
                } else {
                    AnomalySeverity::High
                },
                confidence: 0.85,
                subject: group_name.to_string(),
                description: format!(
                    "Mass group membership change: {} members added, {} removed in {} minutes",
                    members_added, members_removed, time_window_minutes
                ),
                evidence: vec![
                    format!("Members added: {}", members_added),
                    format!("Members removed: {}", members_removed),
                    format!("Time window: {} minutes", time_window_minutes),
                ],
                baseline: None,
                deviation: total_changes as f64,
                recommended_actions: vec![
                    "Verify all membership changes were authorized".to_string(),
                    "Review change logs for source of changes".to_string(),
                    "If unauthorized, revert changes immediately".to_string(),
                ],
            });
        }

        None
    }

    /// Retrieves the behavioral baseline for an entity
    ///
    /// # Arguments
    /// * `entity` - Entity identifier
    ///
    /// # Returns
    /// Reference to baseline if exists, None otherwise
    pub fn get_baseline(&self, entity: &str) -> Option<&BehavioralBaseline> {
        self.baselines.get(entity)
    }

    /// Updates or creates a baseline for an entity
    ///
    /// # Arguments
    /// * `entity` - Entity identifier
    /// * `baseline` - New baseline to store
    pub fn update_baseline(&mut self, entity: String, baseline: BehavioralBaseline) {
        self.baselines.insert(entity, baseline);
    }
}

/// Logon event data structure for anomaly analysis
///
/// Represents a single authentication/logon event with context
/// needed for behavioral analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogonEvent {
    /// When the logon occurred
    pub timestamp: DateTime<Utc>,
    /// Username attempting logon
    pub username: String,
    /// Source IP address (if available)
    pub source_ip: Option<String>,
    /// Whether the logon was successful
    pub success: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_detection() {
        let mut detector = AnomalyDetector::new(0.7);

        let history = vec![
            LogonEvent {
                timestamp: Utc::now() - Duration::days(1),
                username: "testuser".to_string(),
                source_ip: Some("192.168.1.100".to_string()),
                success: true,
            },
            LogonEvent {
                timestamp: Utc::now() - Duration::hours(12),
                username: "testuser".to_string(),
                source_ip: Some("192.168.1.100".to_string()),
                success: true,
            },
        ];

        detector.build_baseline("testuser".to_string(), EntityType::User, &history);

        let anomalous_event = LogonEvent {
            timestamp: Utc::now(),
            username: "testuser".to_string(),
            source_ip: Some("10.0.0.1".to_string()),
            success: true,
        };

        let anomalies = detector.detect_logon_anomalies("testuser", &anomalous_event);
        assert!(!anomalies.is_empty());
    }

    #[test]
    fn test_privilege_escalation_detection() {
        let detector = AnomalyDetector::new(0.8);

        let old_groups = vec!["Users".to_string()];
        let new_groups = vec!["Users".to_string(), "Domain Admins".to_string()];

        let anomalies = detector.detect_privilege_escalation("testuser", &old_groups, &new_groups);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].anomaly_type, AnomalyType::PrivilegeEscalation);
        assert_eq!(anomalies[0].severity, AnomalySeverity::Critical);
    }
}
