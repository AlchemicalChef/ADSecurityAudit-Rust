//! Audit Logging System for Compliance and Security
//!
//! Comprehensive audit logging for all Active Directory operations with:
//! - Persistent storage in SQLite
//! - Tamper-evident logging
//! - Compliance reporting (SOC2, HIPAA, PCI-DSS)
//! - Real-time alerting
//! - Log export capabilities
//!

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{info, error};

/// Audit event severity levels for categorizing security events
///
/// Severity levels help prioritize security responses:
/// - `Info`: Normal operations, informational logging
/// - `Warning`: Unusual but not necessarily dangerous activity
/// - `Error`: Failed operations or security policy violations
/// - `Critical`: Severe security incidents requiring immediate attention
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl Severity {
    fn to_string(&self) -> &str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARNING",
            Severity::Error => "ERROR",
            Severity::Critical => "CRITICAL",
        }
    }

    fn from_string(s: &str) -> Self {
        match s {
            "INFO" => Severity::Info,
            "WARNING" => Severity::Warning,
            "ERROR" => Severity::Error,
            "CRITICAL" => Severity::Critical,
            _ => Severity::Info,
        }
    }
}

/// Audit event categories for organizing security events
///
/// Categories align with security frameworks (NIST, CIS, etc.):
/// - `Authentication`: Login/logout events, credential validation
/// - `Authorization`: Permission checks, access denials
/// - `UserManagement`: User creation, modification, deletion
/// - `GroupManagement`: Group membership changes
/// - `PrivilegeEscalation`: Addition to privileged groups, permission grants
/// - `ConfigurationChange`: GPO changes, domain settings modifications
/// - `DataAccess`: Reading sensitive AD objects
/// - `SecurityAnalysis`: Audit scans, security assessments
/// - `IncidentResponse`: Actions taken during security incidents
/// - `Compliance`: Compliance-related activities
/// - `SystemEvent`: Application lifecycle events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum Category {
    Authentication,
    Authorization,
    UserManagement,
    GroupManagement,
    PrivilegeEscalation,
    ConfigurationChange,
    DataAccess,
    SecurityAnalysis,
    IncidentResponse,
    Compliance,
    SystemEvent,
}

impl Category {
    fn to_string(&self) -> &str {
        match self {
            Category::Authentication => "AUTHENTICATION",
            Category::Authorization => "AUTHORIZATION",
            Category::UserManagement => "USER_MANAGEMENT",
            Category::GroupManagement => "GROUP_MANAGEMENT",
            Category::PrivilegeEscalation => "PRIVILEGE_ESCALATION",
            Category::ConfigurationChange => "CONFIGURATION_CHANGE",
            Category::DataAccess => "DATA_ACCESS",
            Category::SecurityAnalysis => "SECURITY_ANALYSIS",
            Category::IncidentResponse => "INCIDENT_RESPONSE",
            Category::Compliance => "COMPLIANCE",
            Category::SystemEvent => "SYSTEM_EVENT",
        }
    }

    fn from_string(s: &str) -> Self {
        match s {
            "AUTHENTICATION" => Category::Authentication,
            "AUTHORIZATION" => Category::Authorization,
            "USER_MANAGEMENT" => Category::UserManagement,
            "GROUP_MANAGEMENT" => Category::GroupManagement,
            "PRIVILEGE_ESCALATION" => Category::PrivilegeEscalation,
            "CONFIGURATION_CHANGE" => Category::ConfigurationChange,
            "DATA_ACCESS" => Category::DataAccess,
            "SECURITY_ANALYSIS" => Category::SecurityAnalysis,
            "INCIDENT_RESPONSE" => Category::IncidentResponse,
            "COMPLIANCE" => Category::Compliance,
            "SYSTEM_EVENT" => Category::SystemEvent,
            _ => Category::SystemEvent,
        }
    }
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuditEntry {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub domain_id: Option<i64>,
    pub domain_name: Option<String>,
    pub category: Category,
    pub severity: Severity,
    pub action: String,
    pub actor: String,
    pub target: Option<String>,
    pub result: String,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub session_id: Option<String>,
    pub checksum: Option<String>,
}

impl AuditEntry {
    pub(crate) fn new(
        domain_id: Option<i64>,
        domain_name: Option<String>,
        category: Category,
        severity: Severity,
        action: String,
        actor: String,
        target: Option<String>,
        result: String,
    ) -> Self {
        Self {
            id: None,
            timestamp: Utc::now(),
            domain_id,
            domain_name,
            category,
            severity,
            action,
            actor,
            target,
            result,
            details: None,
            ip_address: None,
            session_id: None,
            checksum: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn with_session(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Generates a tamper-evident checksum for integrity verification
    ///
    /// This method creates a SHA256 hash of all critical audit fields:
    /// - timestamp, category, severity, action, actor, target, result, details
    ///
    /// The checksum enables detection of:
    /// - Unauthorized modifications to audit logs
    /// - Database corruption
    /// - Integrity issues during export/import
    ///
    /// # Returns
    /// Hexadecimal string representation of SHA256 hash
    ///
    /// # Security Note
    /// This provides basic integrity checking. For production systems,
    /// consider adding:
    /// - HMAC with secret key
    /// - Digital signatures
    /// - Blockchain-style chaining of entries
    fn generate_checksum(&self) -> String {
        use sha2::{Sha256, Digest};
        // Concatenate all critical fields with pipe separator
        let data = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.timestamp.to_rfc3339(),
            self.category.to_string(),
            self.severity.to_string(),
            self.action,
            self.actor,
            self.target.as_deref().unwrap_or(""),
            self.result,
            self.details.as_deref().unwrap_or("")
        );
        // Compute SHA256 hash
        let hash = Sha256::digest(data.as_bytes());
        // Return as hexadecimal string
        format!("{:x}", hash)
    }
}

/// Query filters for audit logs
#[derive(Debug, Clone, Default)]
pub(crate) struct AuditFilter {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub domain_id: Option<i64>,
    pub category: Option<Category>,
    pub severity: Option<Severity>,
    pub actor: Option<String>,
    pub limit: Option<usize>,
}

/// Compliance report types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum ComplianceStandard {
    SOC2,
    HIPAA,
    PCIDSS,
    GDPR,
    ISO27001,
}

/// Audit log manager with persistent storage
pub(crate) struct AuditLogger {
    db: Arc<Mutex<Connection>>,
    #[allow(dead_code)]
    db_path: PathBuf,
}

impl AuditLogger {
    /// Create a new audit logger
    pub(crate) fn new(db_path: Option<PathBuf>) -> Result<Self> {
        let path = match db_path {
            Some(p) => p,
            None => {
                let mut p = dirs::config_dir()
                    .ok_or_else(|| anyhow!("Cannot determine config directory for audit logs"))?;
                p.push("adsecurityscanner");
                std::fs::create_dir_all(&p).ok();
                p.push("audit_logs.db");
                p
            }
        };

        info!("Initializing audit logger at: {:?}", path);

        let conn = Connection::open(&path)?;

        // Create audit_logs table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                domain_id INTEGER,
                domain_name TEXT,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                target TEXT,
                result TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                session_id TEXT,
                checksum TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Create indices for common queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_logs(timestamp)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_id ON audit_logs(domain_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_category ON audit_logs(category)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_severity ON audit_logs(severity)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_actor ON audit_logs(actor)",
            [],
        )?;

        info!("Audit logger initialized successfully");

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            db_path: path,
        })
    }

    /// Records an audit event to the database with tamper-evident checksum
    ///
    /// This method:
    /// 1. Generates a checksum for integrity verification
    /// 2. Stores the entry in SQLite database
    /// 3. Logs critical events to tracing for real-time monitoring
    ///
    /// # Arguments
    /// * `entry` - The audit entry to log
    ///
    /// # Returns
    /// * `Ok(i64)` - The database ID of the logged entry
    /// * `Err` - If database insertion fails
    ///
    /// # Examples
    /// ```
    /// let entry = AuditEntry::new(
    ///     Some(1),  // domain_id
    ///     Some("example.com".to_string()),
    ///     Category::Authentication,
    ///     Severity::Info,
    ///     "user_login".to_string(),
    ///     "admin@example.com".to_string(),
    ///     None,
    ///     "success".to_string(),
    /// );
    ///
    /// let id = logger.log(entry)?;
    /// ```
    pub(crate) fn log(&self, mut entry: AuditEntry) -> Result<i64> {
        // Generate tamper-evident checksum before storing
        entry.checksum = Some(entry.generate_checksum());

        let db = self.db.lock()
            .map_err(|e| anyhow!("Failed to acquire audit log lock: {}", e))?;

        db.execute(
            "INSERT INTO audit_logs (
                timestamp, domain_id, domain_name, category, severity,
                action, actor, target, result, details,
                ip_address, session_id, checksum
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                entry.timestamp.to_rfc3339(),
                entry.domain_id,
                entry.domain_name,
                entry.category.to_string(),
                entry.severity.to_string(),
                entry.action,
                entry.actor,
                entry.target,
                entry.result,
                entry.details,
                entry.ip_address,
                entry.session_id,
                entry.checksum,
            ],
        )?;

        let id = db.last_insert_rowid();

        // Log critical events to tracing as well
        if entry.severity == Severity::Critical || entry.severity == Severity::Error {
            error!(
                "Audit [{}] {}: {} by {} - {}",
                entry.severity.to_string(),
                entry.category.to_string(),
                entry.action,
                entry.actor,
                entry.result
            );
        }

        Ok(id)
    }

    /// Query audit logs with filters
    pub(crate) fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEntry>> {
        let db = self.db.lock()
            .map_err(|e| anyhow!("Failed to acquire audit log lock: {}", e))?;

        let mut query = "SELECT * FROM audit_logs WHERE 1=1".to_string();
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(start) = &filter.start_time {
            query.push_str(" AND timestamp >= ?");
            params_vec.push(Box::new(start.to_rfc3339()));
        }

        if let Some(end) = &filter.end_time {
            query.push_str(" AND timestamp <= ?");
            params_vec.push(Box::new(end.to_rfc3339()));
        }

        if let Some(domain_id) = filter.domain_id {
            query.push_str(" AND domain_id = ?");
            params_vec.push(Box::new(domain_id));
        }

        if let Some(category) = &filter.category {
            query.push_str(" AND category = ?");
            params_vec.push(Box::new(category.to_string()));
        }

        if let Some(severity) = &filter.severity {
            query.push_str(" AND severity = ?");
            params_vec.push(Box::new(severity.to_string()));
        }

        if let Some(actor) = &filter.actor {
            query.push_str(" AND actor LIKE ?");
            params_vec.push(Box::new(format!("%{}%", actor)));
        }

        query.push_str(" ORDER BY timestamp DESC");

        // Validate and apply LIMIT clause with bounds checking
        if let Some(limit) = filter.limit {
            // Enforce maximum limit to prevent resource exhaustion
            const MAX_LIMIT: usize = 10000;
            if limit == 0 {
                return Err(anyhow!("Invalid limit: must be greater than 0"));
            }
            if limit > MAX_LIMIT {
                return Err(anyhow!("Invalid limit: maximum allowed is {}", MAX_LIMIT));
            }
            // Safe to use format! here since limit is validated usize
            query.push_str(&format!(" LIMIT {}", limit));
        }

        let mut stmt = db.prepare(&query)?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();

        let entries = stmt.query_map(params_refs.as_slice(), |row| {
            let timestamp_str: String = row.get(1)?;
            let timestamp = timestamp_str.parse::<DateTime<Utc>>()
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(e)
                ))?;

            Ok(AuditEntry {
                id: row.get(0)?,
                timestamp,
                domain_id: row.get(2)?,
                domain_name: row.get(3)?,
                category: Category::from_string(&row.get::<_, String>(4)?),
                severity: Severity::from_string(&row.get::<_, String>(5)?),
                action: row.get(6)?,
                actor: row.get(7)?,
                target: row.get(8)?,
                result: row.get(9)?,
                details: row.get(10)?,
                ip_address: row.get(11)?,
                session_id: row.get(12)?,
                checksum: row.get(13)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    /// Get audit statistics
    pub(crate) fn get_statistics(&self, filter: AuditFilter) -> Result<AuditStatistics> {
        let entries = self.query(filter)?;

        let mut stats = AuditStatistics::default();
        stats.total_events = entries.len();

        for entry in entries {
            match entry.severity {
                Severity::Info => stats.info_count += 1,
                Severity::Warning => stats.warning_count += 1,
                Severity::Error => stats.error_count += 1,
                Severity::Critical => stats.critical_count += 1,
            }

            *stats.events_by_category.entry(entry.category.to_string().to_owned()).or_insert(0) += 1;
        }

        Ok(stats)
    }

    /// Generates a compliance report for a specific standard and time period
    ///
    /// This method creates audit reports aligned with major compliance frameworks:
    /// - SOC2: Focus on access controls and data security
    /// - HIPAA: Electronic protected health information (ePHI) access
    /// - PCI-DSS: Cardholder data environment access and changes
    /// - GDPR: Personal data processing activities
    /// - ISO27001: Information security management
    ///
    /// # Arguments
    /// * `standard` - The compliance standard to report on
    /// * `start_time` - Beginning of the reporting period
    /// * `end_time` - End of the reporting period
    ///
    /// # Returns
    /// A `ComplianceReport` containing:
    /// - Filtered audit events relevant to the standard
    /// - Statistics on event types and severity
    /// - Critical findings requiring attention
    /// - Automated recommendations for compliance
    ///
    /// # Examples
    /// ```
    /// use chrono::{Utc, Duration};
    ///
    /// let end = Utc::now();
    /// let start = end - Duration::days(30);
    ///
    /// let report = logger.generate_compliance_report(
    ///     ComplianceStandard::SOC2,
    ///     start,
    ///     end
    /// )?;
    ///
    /// println!("Total events: {}", report.total_events);
    /// println!("Critical findings: {}", report.critical_findings.len());
    /// ```
    pub(crate) fn generate_compliance_report(
        &self,
        standard: ComplianceStandard,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<ComplianceReport> {
        let filter = AuditFilter {
            start_time: Some(start_time),
            end_time: Some(end_time),
            ..Default::default()
        };

        let entries = self.query(filter)?;
        let statistics = self.get_statistics(AuditFilter {
            start_time: Some(start_time),
            end_time: Some(end_time),
            ..Default::default()
        })?;

        // Filter entries based on compliance standard requirements
        let relevant_entries: Vec<AuditEntry> = match &standard {
            ComplianceStandard::SOC2 => {
                entries.into_iter()
                    .filter(|e| matches!(e.category,
                        Category::Authentication |
                        Category::Authorization |
                        Category::DataAccess |
                        Category::ConfigurationChange
                    ))
                    .collect()
            }
            ComplianceStandard::HIPAA => {
                entries.into_iter()
                    .filter(|e| matches!(e.category,
                        Category::DataAccess |
                        Category::Authentication |
                        Category::Authorization
                    ))
                    .collect()
            }
            ComplianceStandard::PCIDSS => {
                entries.into_iter()
                    .filter(|e| matches!(e.category,
                        Category::Authentication |
                        Category::Authorization |
                        Category::DataAccess |
                        Category::ConfigurationChange |
                        Category::PrivilegeEscalation
                    ))
                    .collect()
            }
            ComplianceStandard::GDPR | ComplianceStandard::ISO27001 => {
                entries
            }
        };

        Ok(ComplianceReport {
            standard,
            period_start: start_time,
            period_end: end_time,
            generated_at: Utc::now(),
            total_events: relevant_entries.len(),
            statistics,
            critical_findings: relevant_entries.iter()
                .filter(|e| e.severity == Severity::Critical)
                .cloned()
                .collect(),
            recommendations: Self::generate_recommendations(&standard, &relevant_entries),
        })
    }

    fn generate_recommendations(standard: &ComplianceStandard, entries: &[AuditEntry]) -> Vec<String> {
        let mut recommendations = Vec::new();

        let failed_auths = entries.iter()
            .filter(|e| e.category == Category::Authentication && e.result.contains("failed"))
            .count();

        if failed_auths > 10 {
            recommendations.push(format!(
                "High number of failed authentication attempts detected ({}). Consider implementing account lockout policies.",
                failed_auths
            ));
        }

        let priv_escalations = entries.iter()
            .filter(|e| e.category == Category::PrivilegeEscalation)
            .count();

        if priv_escalations > 0 {
            recommendations.push(format!(
                "Detected {} privilege escalation events. Review and verify all changes were authorized.",
                priv_escalations
            ));
        }

        match standard {
            ComplianceStandard::SOC2 => {
                recommendations.push("Ensure all access to sensitive resources is logged and monitored.".to_string());
                recommendations.push("Implement multi-factor authentication for administrative access.".to_string());
            }
            ComplianceStandard::HIPAA => {
                recommendations.push("Maintain audit logs for minimum 6 years as per HIPAA requirements.".to_string());
                recommendations.push("Ensure all PHI access is logged and regularly reviewed.".to_string());
            }
            ComplianceStandard::PCIDSS => {
                recommendations.push("Maintain audit logs for minimum 1 year, with 3 months immediately available.".to_string());
                recommendations.push("Implement automated log review and anomaly detection.".to_string());
            }
            _ => {}
        }

        recommendations
    }

    /// Export audit logs to file
    #[allow(dead_code)]
    pub(crate) fn export_to_file(&self, filter: AuditFilter, path: PathBuf) -> Result<usize> {
        let entries = self.query(filter)?;
        let json = serde_json::to_string_pretty(&entries)?;
        std::fs::write(&path, json)?;
        info!("Exported {} audit entries to {:?}", entries.len(), path);
        Ok(entries.len())
    }

    /// Verify log integrity using checksums
    #[allow(dead_code)]
    pub(crate) fn verify_integrity(&self) -> Result<IntegrityReport> {
        let all_entries = self.query(AuditFilter::default())?;

        let mut report = IntegrityReport {
            total_entries: all_entries.len(),
            verified: 0,
            tampered: Vec::new(),
        };

        for entry in all_entries {
            let expected_checksum = entry.generate_checksum();
            if entry.checksum.as_deref() == Some(&expected_checksum) {
                report.verified += 1;
            } else {
                report.tampered.push(entry.id.unwrap_or(0));
            }
        }

        Ok(report)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct AuditStatistics {
    pub total_events: usize,
    pub critical_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub events_by_category: std::collections::HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ComplianceReport {
    pub standard: ComplianceStandard,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub generated_at: DateTime<Utc>,
    pub total_events: usize,
    pub statistics: AuditStatistics,
    pub critical_findings: Vec<AuditEntry>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct IntegrityReport {
    pub total_entries: usize,
    pub verified: usize,
    pub tampered: Vec<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_logging() {
        let logger = AuditLogger::new(None).unwrap();

        let entry = AuditEntry::new(
            Some(1),
            Some("test.local".to_string()),
            Category::Authentication,
            Severity::Info,
            "user_login".to_string(),
            "admin@test.local".to_string(),
            None,
            "success".to_string(),
        );

        let id = logger.log(entry).unwrap();
        assert!(id > 0);

        let results = logger.query(AuditFilter::default()).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn test_integrity_check() {
        let logger = AuditLogger::new(None).unwrap();

        let entry = AuditEntry::new(
            None,
            None,
            Category::SystemEvent,
            Severity::Info,
            "test_action".to_string(),
            "system".to_string(),
            None,
            "success".to_string(),
        );

        logger.log(entry).unwrap();

        let report = logger.verify_integrity().unwrap();
        assert_eq!(report.verified, report.total_entries);
        assert!(report.tampered.is_empty());
    }
}
