//! Risk Scoring Engine for Active Directory Security
//!
//! Comprehensive risk assessment and scoring system that evaluates:
//! - User account risk levels
//! - Domain security posture
//! - Privilege escalation paths
//! - Configuration vulnerabilities
//!
// Allow unused code - risk visualization methods for future UI features
#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Risk severity levels with score-based classification
///
/// Categorizes risk scores into four levels:
/// - **Low**: 0-39 points - Minimal security concerns
/// - **Medium**: 40-59 points - Moderate attention required
/// - **High**: 60-79 points - Significant security risk
/// - **Critical**: 80-100 points - Immediate action required
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Minimal risk (0-39 points)
    Low,
    /// Moderate risk requiring attention (40-59 points)
    Medium,
    /// Significant risk requiring prompt action (60-79 points)
    High,
    /// Critical risk requiring immediate action (80-100 points)
    Critical,
}

impl RiskLevel {
    /// Converts a numeric score (0-100) to a risk level category
    ///
    /// # Arguments
    /// * `score` - Risk score between 0.0 and 100.0
    ///
    /// # Returns
    /// Appropriate RiskLevel enum variant
    ///
    /// # Examples
    /// ```
    /// let level = RiskLevel::from_score(85.0);
    /// assert_eq!(level, RiskLevel::Critical);
    /// ```
    pub fn from_score(score: f64) -> Self {
        if score >= 80.0 {
            RiskLevel::Critical
        } else if score >= 60.0 {
            RiskLevel::High
        } else if score >= 40.0 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }

    /// Returns hex color code for UI visualization
    ///
    /// # Returns
    /// Hex color string for displaying risk level in UI
    pub fn to_color(&self) -> &str {
        match self {
            RiskLevel::Low => "#10b981",      // green
            RiskLevel::Medium => "#f59e0b",   // yellow
            RiskLevel::High => "#ef4444",     // red
            RiskLevel::Critical => "#7f1d1d", // dark red
        }
    }
}

/// Individual risk factor contributing to overall security score
///
/// Each risk factor represents a specific security concern with its own
/// weight, score, supporting evidence, and mitigation strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Human-readable name of the risk factor
    pub name: String,
    /// Detailed description of what this factor represents
    pub description: String,
    /// Weight of this factor in overall score calculation (0.0-1.0)
    pub weight: f64,
    /// Individual score for this factor (0.0-100.0)
    pub score: f64,
    /// Supporting evidence for this risk assessment
    pub evidence: Vec<String>,
    /// Recommended mitigation steps
    pub mitigation: String,
}

/// Comprehensive risk assessment for an individual user account
///
/// Evaluates multiple security factors to produce an overall risk score
/// with specific recommendations for risk mitigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRiskScore {
    /// Distinguished Name of the user in Active Directory
    pub user_dn: String,
    /// Username (samAccountName)
    pub username: String,
    /// Weighted overall risk score (0.0-100.0)
    pub overall_score: f64,
    /// Categorized risk level based on overall score
    pub risk_level: RiskLevel,
    /// Individual risk factors contributing to the score
    pub factors: Vec<RiskFactor>,
    /// Timestamp when this assessment was performed
    pub assessed_at: DateTime<Utc>,
    /// Prioritized list of recommended actions
    pub recommendations: Vec<String>,
}

/// Comprehensive domain-wide security risk assessment
///
/// Evaluates entire AD domain across multiple security categories
/// to produce an overall security posture score with trend analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRiskScore {
    /// Database ID of the domain (if stored)
    pub domain_id: Option<i64>,
    /// Fully qualified domain name
    pub domain_name: String,
    /// Weighted overall risk score (0.0-100.0)
    pub overall_score: f64,
    /// Categorized risk level based on overall score
    pub risk_level: RiskLevel,
    /// Risk breakdown by security category
    pub categories: HashMap<String, CategoryRisk>,
    /// Timestamp when this assessment was performed
    pub assessed_at: DateTime<Utc>,
    /// Risk trend compared to previous assessment
    pub trend: RiskTrend,
    /// Top 5 most critical risks requiring attention
    pub top_risks: Vec<RiskFactor>,
    /// Prioritized list of recommended actions
    pub recommendations: Vec<String>,
}

/// Risk assessment for a specific security category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryRisk {
    /// Human-readable category name
    pub category: String,
    /// Category risk score (0.0-100.0)
    pub score: f64,
    /// Categorized risk level for this category
    pub risk_level: RiskLevel,
    /// Number of issues detected in this category
    pub issues_count: usize,
}

/// Risk trend indicator comparing current to previous assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskTrend {
    /// Security posture has improved (score decreased by >5 points)
    Improving,
    /// Security posture is stable (score changed by ≤5 points)
    Stable,
    /// Security posture is degrading (score increased by >5 points)
    Degrading,
}

/// Risk scoring engine
pub struct RiskScoringEngine;

impl RiskScoringEngine {
    /// Calculates comprehensive risk score for an individual user account
    ///
    /// Evaluates multiple security factors with different weights:
    /// - Privileged account inactivity (25% weight)
    /// - Password age (15-20% weight, higher for privileged accounts)
    /// - Failed logon attempts (15% weight)
    /// - Kerberoastable SPNs (20% weight)
    /// - Unexpected admin rights (20% weight)
    ///
    /// # Arguments
    /// * `user_dn` - Distinguished Name of the user
    /// * `username` - samAccountName of the user
    /// * `is_privileged` - Whether user is in privileged groups
    /// * `_is_enabled` - Account enabled status (reserved for future use)
    /// * `last_logon` - Timestamp of last successful logon
    /// * `password_last_set` - Timestamp when password was last changed
    /// * `privileged_groups` - List of privileged group memberships
    /// * `has_admin_rights` - Whether user has administrative privileges
    /// * `failed_logon_count` - Number of recent failed logon attempts
    /// * `service_principal_names` - List of SPNs (Kerberoastable if present)
    ///
    /// # Returns
    /// `UserRiskScore` with overall score, risk level, factors, and recommendations
    ///
    /// # Algorithm
    /// 1. Evaluate each risk factor individually (inactivity, password age, etc.)
    /// 2. Calculate weighted score for each factor based on severity
    /// 3. Compute overall score as weighted average of all factors
    /// 4. Categorize into risk level (Low/Medium/High/Critical)
    /// 5. Generate prioritized recommendations
    ///
    /// # Examples
    /// ```
    /// let score = RiskScoringEngine::score_user(
    ///     "CN=John Doe,OU=Users,DC=example,DC=com",
    ///     "jdoe",
    ///     true,  // is privileged
    ///     true,  // is enabled
    ///     Some(Utc::now() - Duration::days(100)),  // inactive for 100 days
    ///     Some(Utc::now() - Duration::days(400)),  // password 400 days old
    ///     vec!["Domain Admins".to_string()],
    ///     true,  // has admin rights
    ///     5,     // 5 failed logons
    ///     vec!["HTTP/service.example.com".to_string()],  // Kerberoastable
    /// );
    /// // Returns high/critical score due to inactive privileged account with old password
    /// ```
    pub fn score_user(
        user_dn: &str,
        username: &str,
        is_privileged: bool,
        _is_enabled: bool,  // Reserved for future use in account status checks
        last_logon: Option<DateTime<Utc>>,
        password_last_set: Option<DateTime<Utc>>,
        privileged_groups: Vec<String>,
        has_admin_rights: bool,
        failed_logon_count: u32,
        service_principal_names: Vec<String>,
    ) -> UserRiskScore {
        let mut factors = Vec::new();
        let mut total_weighted_score = 0.0;
        let mut total_weight = 0.0;

        // Factor 1: Privileged account without recent activity
        if is_privileged {
            let inactivity_score = if let Some(last_logon) = last_logon {
                let days_inactive = Utc::now().signed_duration_since(last_logon).num_days();
                if days_inactive > 90 {
                    85.0
                } else if days_inactive > 30 {
                    60.0
                } else {
                    20.0
                }
            } else {
                90.0 // No logon recorded = high risk
            };

            let weight = 0.25;
            total_weighted_score += inactivity_score * weight;
            total_weight += weight;

            factors.push(RiskFactor {
                name: "Privileged Account Inactivity".to_string(),
                description: "Privileged account with no recent activity".to_string(),
                weight,
                score: inactivity_score,
                evidence: vec![
                    format!("Last logon: {}", last_logon.map(|d| d.to_rfc2822()).unwrap_or("Never".to_string())),
                    format!("Privileged groups: {}", privileged_groups.join(", ")),
                ],
                mitigation: "Consider disabling inactive privileged accounts or requiring re-authentication.".to_string(),
            });
        }

        // Factor 2: Password age
        if let Some(pwd_last_set) = password_last_set {
            let days_old = Utc::now().signed_duration_since(pwd_last_set).num_days();
            let pwd_score = if days_old > 365 {
                90.0
            } else if days_old > 180 {
                70.0
            } else if days_old > 90 {
                40.0
            } else {
                10.0
            };

            let weight = if is_privileged { 0.20 } else { 0.15 };
            total_weighted_score += pwd_score * weight;
            total_weight += weight;

            factors.push(RiskFactor {
                name: "Password Age".to_string(),
                description: "Account password hasn't been changed recently".to_string(),
                weight,
                score: pwd_score,
                evidence: vec![
                    format!("Password last set: {}", pwd_last_set.to_rfc2822()),
                    format!("Days old: {}", days_old),
                ],
                mitigation: "Enforce regular password rotation policy.".to_string(),
            });
        }

        // Factor 3: Excessive failed logons
        if failed_logon_count > 0 {
            let failed_logon_score = (failed_logon_count as f64 * 10.0).min(100.0);
            let weight = 0.15;
            total_weighted_score += failed_logon_score * weight;
            total_weight += weight;

            factors.push(RiskFactor {
                name: "Failed Logon Attempts".to_string(),
                description: "Multiple failed logon attempts detected".to_string(),
                weight,
                score: failed_logon_score,
                evidence: vec![
                    format!("Failed logon count: {}", failed_logon_count),
                ],
                mitigation: "Investigate potential brute force attacks. Consider account lockout policies.".to_string(),
            });
        }

        // Factor 4: Service Principal Names (Kerberoastable)
        if !service_principal_names.is_empty() {
            let spn_score = if is_privileged { 80.0 } else { 50.0 };
            let weight = 0.20;
            total_weighted_score += spn_score * weight;
            total_weight += weight;

            factors.push(RiskFactor {
                name: "Kerberoastable Account".to_string(),
                description: "Account has SPNs and may be vulnerable to Kerberoasting".to_string(),
                weight,
                score: spn_score,
                evidence: vec![
                    format!("SPNs: {}", service_principal_names.join(", ")),
                ],
                mitigation: "Use strong passwords (>25 characters) and consider using Group Managed Service Accounts.".to_string(),
            });
        }

        // Factor 5: Admin rights
        if has_admin_rights && !is_privileged {
            let admin_score = 75.0;
            let weight = 0.20;
            total_weighted_score += admin_score * weight;
            total_weight += weight;

            factors.push(RiskFactor {
                name: "Unexpected Admin Rights".to_string(),
                description: "Non-privileged account has administrative privileges".to_string(),
                weight,
                score: admin_score,
                evidence: vec![
                    "Account has local or domain admin rights".to_string(),
                ],
                mitigation: "Review and remove unnecessary administrative privileges.".to_string(),
            });
        }

        let overall_score = if total_weight > 0.0 {
            total_weighted_score / total_weight
        } else {
            0.0
        };

        let risk_level = RiskLevel::from_score(overall_score);

        let recommendations = Self::generate_user_recommendations(&factors, is_privileged);

        UserRiskScore {
            user_dn: user_dn.to_string(),
            username: username.to_string(),
            overall_score,
            risk_level,
            factors,
            assessed_at: Utc::now(),
            recommendations,
        }
    }

    /// Calculates comprehensive risk score for entire Active Directory domain
    ///
    /// Evaluates domain security across six major categories:
    /// - KRBTGT Security (25% weight) - Password age of KRBTGT account
    /// - Privileged Accounts (20% weight) - Stale admin account ratio
    /// - Password Security (15% weight) - Weak password prevalence
    /// - Group Policy Security (15% weight) - GPO configuration issues
    /// - Delegation & Permissions (15% weight) - Dangerous delegation patterns
    /// - Trust Relationships (10% weight) - Trust configuration issues
    ///
    /// # Arguments
    /// * `domain_id` - Database ID of the domain (if stored)
    /// * `domain_name` - Fully qualified domain name
    /// * `krbtgt_age_days` - Age of KRBTGT password in days
    /// * `admin_count` - Total number of privileged accounts
    /// * `stale_admin_count` - Number of inactive privileged accounts
    /// * `weak_password_count` - Number of accounts with weak passwords
    /// * `gpo_issues_count` - Number of Group Policy security issues
    /// * `delegation_issues_count` - Number of dangerous delegation patterns
    /// * `trust_issues_count` - Number of trust configuration issues
    /// * `permission_issues_count` - Number of permission security issues
    /// * `previous_score` - Previous assessment score for trend analysis
    ///
    /// # Returns
    /// `DomainRiskScore` with overall score, category breakdown, trend, and recommendations
    ///
    /// # Algorithm
    /// 1. Evaluate each security category independently
    /// 2. Score KRBTGT based on password age (>365 days = critical)
    /// 3. Calculate stale admin ratio and score
    /// 4. Score password security based on weak password count
    /// 5. Evaluate GPO, delegation, and trust issues
    /// 6. Compute weighted overall score across all categories
    /// 7. Compare to previous score to determine trend
    /// 8. Identify top 5 risks and generate recommendations
    ///
    /// # Examples
    /// ```
    /// let score = RiskScoringEngine::score_domain(
    ///     Some(1),
    ///     "example.com".to_string(),
    ///     400,  // KRBTGT password 400 days old (critical)
    ///     50,   // 50 privileged accounts
    ///     10,   // 10 are stale (20% - high risk)
    ///     25,   // 25 weak passwords
    ///     5,    // 5 GPO issues
    ///     3,    // 3 delegation issues
    ///     2,    // 2 trust issues
    ///     4,    // 4 permission issues
    ///     Some(65.0),  // Previous score for comparison
    /// );
    /// // Returns high score due to old KRBTGT and stale admins
    /// ```
    pub fn score_domain(
        domain_id: Option<i64>,
        domain_name: String,
        krbtgt_age_days: i64,
        admin_count: usize,
        stale_admin_count: usize,
        weak_password_count: usize,
        gpo_issues_count: usize,
        delegation_issues_count: usize,
        trust_issues_count: usize,
        permission_issues_count: usize,
        previous_score: Option<f64>,
    ) -> DomainRiskScore {
        let mut categories = HashMap::new();
        let mut top_risks = Vec::new();

        // Category 1: KRBTGT Security
        let krbtgt_score = if krbtgt_age_days > 365 {
            100.0
        } else if krbtgt_age_days > 180 {
            75.0
        } else if krbtgt_age_days > 90 {
            40.0
        } else {
            10.0
        };

        categories.insert("krbtgt_security".to_string(), CategoryRisk {
            category: "KRBTGT Security".to_string(),
            score: krbtgt_score,
            risk_level: RiskLevel::from_score(krbtgt_score),
            issues_count: if krbtgt_age_days > 180 { 1 } else { 0 },
        });

        if krbtgt_age_days > 180 {
            top_risks.push(RiskFactor {
                name: "Outdated KRBTGT Password".to_string(),
                description: format!("KRBTGT password is {} days old", krbtgt_age_days),
                weight: 0.25,
                score: krbtgt_score,
                evidence: vec![format!("KRBTGT age: {} days", krbtgt_age_days)],
                mitigation: "Rotate KRBTGT password immediately using the built-in rotation tool.".to_string(),
            });
        }

        // Category 2: Privileged Account Management
        let stale_ratio = if admin_count > 0 {
            (stale_admin_count as f64 / admin_count as f64) * 100.0
        } else {
            0.0
        };
        let admin_score = stale_ratio;

        categories.insert("privileged_accounts".to_string(), CategoryRisk {
            category: "Privileged Accounts".to_string(),
            score: admin_score,
            risk_level: RiskLevel::from_score(admin_score),
            issues_count: stale_admin_count,
        });

        if stale_admin_count > 0 {
            top_risks.push(RiskFactor {
                name: "Stale Privileged Accounts".to_string(),
                description: format!("{} privileged accounts are inactive", stale_admin_count),
                weight: 0.20,
                score: admin_score,
                evidence: vec![format!("{}/{} privileged accounts are stale", stale_admin_count, admin_count)],
                mitigation: "Disable or remove inactive privileged accounts.".to_string(),
            });
        }

        // Category 3: Password Security
        let password_score = (weak_password_count as f64 * 5.0).min(100.0);
        categories.insert("password_security".to_string(), CategoryRisk {
            category: "Password Security".to_string(),
            score: password_score,
            risk_level: RiskLevel::from_score(password_score),
            issues_count: weak_password_count,
        });

        // Category 4: GPO Security
        let gpo_score = (gpo_issues_count as f64 * 10.0).min(100.0);
        categories.insert("gpo_security".to_string(), CategoryRisk {
            category: "Group Policy Security".to_string(),
            score: gpo_score,
            risk_level: RiskLevel::from_score(gpo_score),
            issues_count: gpo_issues_count,
        });

        // Category 5: Delegation and Permissions
        let delegation_score = (delegation_issues_count as f64 * 15.0).min(100.0);
        categories.insert("delegation".to_string(), CategoryRisk {
            category: "Delegation & Permissions".to_string(),
            score: delegation_score,
            risk_level: RiskLevel::from_score(delegation_score),
            issues_count: delegation_issues_count + permission_issues_count,
        });

        // Category 6: Trust Relationships
        let trust_score = (trust_issues_count as f64 * 20.0).min(100.0);
        categories.insert("trust_relationships".to_string(), CategoryRisk {
            category: "Trust Relationships".to_string(),
            score: trust_score,
            risk_level: RiskLevel::from_score(trust_score),
            issues_count: trust_issues_count,
        });

        // Calculate overall score (weighted average)
        let overall_score = krbtgt_score * 0.25 +
            admin_score * 0.20 +
            password_score * 0.15 +
            gpo_score * 0.15 +
            delegation_score * 0.15 +
            trust_score * 0.10;

        let risk_level = RiskLevel::from_score(overall_score);

        // Determine trend
        let trend = if let Some(prev) = previous_score {
            if overall_score < prev - 5.0 {
                RiskTrend::Improving
            } else if overall_score > prev + 5.0 {
                RiskTrend::Degrading
            } else {
                RiskTrend::Stable
            }
        } else {
            RiskTrend::Stable
        };

        // Sort top risks by score
        top_risks.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        let top_risks: Vec<RiskFactor> = top_risks.into_iter().take(5).collect();

        let recommendations = Self::generate_domain_recommendations(&categories, &top_risks);

        DomainRiskScore {
            domain_id,
            domain_name,
            overall_score,
            risk_level,
            categories,
            assessed_at: Utc::now(),
            trend,
            top_risks,
            recommendations,
        }
    }

    /// Generates prioritized recommendations for user risk mitigation
    ///
    /// # Arguments
    /// * `factors` - List of risk factors identified for the user
    /// * `is_privileged` - Whether the user has privileged access
    ///
    /// # Returns
    /// List of up to 5 prioritized recommendations
    ///
    /// # Algorithm
    /// 1. Add baseline recommendations for privileged accounts (MFA, dedicated accounts)
    /// 2. Include mitigation steps for all high-severity factors (score >70)
    /// 3. Deduplicate recommendations
    /// 4. Limit to top 5 most important actions
    fn generate_user_recommendations(factors: &[RiskFactor], is_privileged: bool) -> Vec<String> {
        let mut recs = Vec::new();

        if is_privileged {
            recs.push("Use dedicated admin accounts for privileged operations only.".to_string());
            recs.push("Enable multi-factor authentication for all privileged accounts.".to_string());
        }

        for factor in factors {
            if factor.score > 70.0 {
                recs.push(factor.mitigation.clone());
            }
        }

        recs.dedup();
        recs.truncate(5);
        recs
    }

    /// Generates prioritized recommendations for domain-wide risk mitigation
    ///
    /// # Arguments
    /// * `categories` - Risk assessment breakdown by category
    /// * `top_risks` - List of highest-priority risks
    ///
    /// # Returns
    /// List of up to 8 prioritized domain-wide recommendations
    ///
    /// # Algorithm
    /// 1. Identify Critical/High risk categories
    /// 2. Add category-specific recommendations (KRBTGT rotation, admin cleanup, etc.)
    /// 3. Include mitigation steps from top 3 risks
    /// 4. Add baseline security recommendations (monitoring, regular audits)
    /// 5. Deduplicate and limit to 8 recommendations
    fn generate_domain_recommendations(
        categories: &HashMap<String, CategoryRisk>,
        top_risks: &[RiskFactor],
    ) -> Vec<String> {
        let mut recs = Vec::new();

        // Add recommendations based on critical categories
        for (_, cat) in categories {
            if cat.risk_level == RiskLevel::Critical || cat.risk_level == RiskLevel::High {
                match cat.category.as_str() {
                    "KRBTGT Security" => {
                        recs.push("Rotate KRBTGT password immediately using the secure rotation process.".to_string());
                    }
                    "Privileged Accounts" => {
                        recs.push("Audit and clean up inactive privileged accounts.".to_string());
                    }
                    "Password Security" => {
                        recs.push("Enforce strong password policies and implement password filters.".to_string());
                    }
                    "Group Policy Security" => {
                        recs.push("Review and remediate GPO security issues.".to_string());
                    }
                    _ => {}
                }
            }
        }

        // Add top risk mitigations
        for risk in top_risks.iter().take(3) {
            recs.push(risk.mitigation.clone());
        }

        recs.push("Implement continuous monitoring and alerting for security events.".to_string());
        recs.push("Schedule regular security audits and penetration testing.".to_string());

        recs.dedup();
        recs.truncate(8);
        recs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_risk_scoring() {
        let score = RiskScoringEngine::score_user(
            "CN=John Doe,OU=Users,DC=example,DC=com",
            "jdoe",
            true,
            true,
            Some(Utc::now() - Duration::days(100)),
            Some(Utc::now() - Duration::days(400)),
            vec!["Domain Admins".to_string()],
            true,
            5,
            vec!["HTTP/service.example.com".to_string()],
        );

        assert!(score.overall_score > 0.0);
        assert!(!score.factors.is_empty());
        assert!(!score.recommendations.is_empty());
    }

    #[test]
    fn test_domain_risk_scoring() {
        let score = RiskScoringEngine::score_domain(
            Some(1),
            "example.com".to_string(),
            400,  // KRBTGT age
            50,   // admin count
            10,   // stale admins
            25,   // weak passwords
            5,    // GPO issues
            3,    // delegation issues
            2,    // trust issues
            4,    // permission issues
            None,
        );

        assert!(score.overall_score > 0.0);
        assert!(!score.categories.is_empty());
        assert!(!score.top_risks.is_empty());
        assert!(!score.recommendations.is_empty());
    }

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(90.0), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(70.0), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(50.0), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(20.0), RiskLevel::Low);
    }
}
