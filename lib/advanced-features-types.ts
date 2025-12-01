/**
 * Advanced Features Type Definitions
 *
 * TypeScript interfaces mirroring Rust backend structures for
 * advanced platform features including audit logging, risk scoring,
 * anomaly detection, and caching.
 *
 * @module lib/advanced-features-types
 *
 * Type Categories:
 *
 * Audit Logging:
 * - AuditEntry: Individual log entries with severity and category
 * - ComplianceStandard: SOC2, HIPAA, PCI-DSS, GDPR, ISO27001
 *
 * Risk Scoring:
 * - RiskScore: Calculated risk with category breakdown
 * - RiskLevel: Critical, High, Medium, Low, Info
 *
 * Anomaly Detection:
 * - Anomaly: Detected behavioral anomaly with evidence
 * - BehavioralBaseline: Learned normal behavior patterns
 *
 * Caching:
 * - CacheStats: Hit rate, size, eviction metrics
 * - CacheEntry: Cached data with TTL tracking
 *
 * These types ensure type safety across the frontend-backend boundary
 * and enable IDE autocompletion for all API responses.
 */

// TypeScript types for IRP Platform Advanced Features
// Mirrors Rust backend structures for audit logging, risk scoring, anomaly detection, and cache

// ============================================================================
// AUDIT LOGGING TYPES
// ============================================================================

export type AuditSeverity = 'info' | 'warning' | 'error' | 'critical'

export type AuditCategory =
  | 'authentication'
  | 'authorization'
  | 'user_management'
  | 'group_management'
  | 'privilege_escalation'
  | 'configuration_change'
  | 'data_access'
  | 'security_analysis'
  | 'incident_response'
  | 'compliance'
  | 'system_event'

export type ComplianceStandard = 'SOC2' | 'HIPAA' | 'PCI_DSS' | 'GDPR' | 'ISO27001'

export interface AuditEntry {
  id: number
  timestamp: string // ISO 8601
  domain_id: number | null
  domain_name: string | null
  category: AuditCategory
  severity: AuditSeverity
  action: string
  actor: string
  target: string | null
  result: string
  metadata: string | null
  checksum: string
}

export interface AuditFilter {
  start_time?: string // ISO 8601
  end_time?: string // ISO 8601
  domain_id?: number
  category?: AuditCategory
  severity?: AuditSeverity
  actor?: string
  limit?: number
}

export interface AuditStatistics {
  total_events: number
  events_by_category: Record<AuditCategory, number>
  events_by_severity: Record<AuditSeverity, number>
  unique_actors: number
  domains_involved: number
}

export interface ComplianceReport {
  standard: ComplianceStandard
  start_time: string
  end_time: string
  total_events: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  recommendations: string[]
  findings: AuditEntry[]
}

// ============================================================================
// RISK SCORING TYPES
// ============================================================================

export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical'

export interface RiskFactor {
  name: string
  description: string
  weight: number // 0.0 - 1.0
  score: number // 0.0 - 100.0
  evidence: string[]
  mitigation: string
}

export interface UserRiskScore {
  user_dn: string
  username: string
  overall_score: number // 0.0 - 100.0
  risk_level: RiskLevel
  factors: RiskFactor[]
  timestamp: string
  recommendations: string[]
}

export interface CategoryRisk {
  category: string
  score: number
  risk_level: RiskLevel
  issue_count: number
}

export type RiskTrend = 'Improving' | 'Stable' | 'Degrading'

export interface DomainRiskScore {
  domain_id: number | null
  domain_name: string
  overall_score: number // 0.0 - 100.0
  risk_level: RiskLevel
  category_breakdown: CategoryRisk[]
  trend: RiskTrend
  top_risks: string[]
  recommendations: string[]
  timestamp: string
}

// ============================================================================
// ANOMALY DETECTION TYPES
// ============================================================================

export type AnomalySeverity = 'Low' | 'Medium' | 'High' | 'Critical'

export type AnomalyType =
  | 'UnusualLogonTime'
  | 'UnusualLogonLocation'
  | 'PrivilegeEscalation'
  | 'MassGroupChange'
  | 'RapidFireLogons'
  | 'SuspiciousQuery'
  | 'ConfigurationChange'
  | 'UnusualUserCreation'
  | 'BruteForceAttempt'
  | 'LateralMovement'

export type EntityType = 'user' | 'computer' | 'group' | 'service_account'

export interface Anomaly {
  id: string
  detected_at: string
  anomaly_type: AnomalyType
  severity: AnomalySeverity
  confidence: number // 0.0 - 1.0
  subject: string
  description: string
  evidence: string[]
  baseline: string | null
  deviation: string | null
  recommended_actions: string[]
}

export interface LogonEvent {
  timestamp: string
  username: string
  source_ip: string
  success: boolean
}

export interface BehavioralBaseline {
  entity: string
  entity_type: EntityType
  created_at: string
  updated_at: string
  typical_logon_hours: number[]
  typical_logon_days: number[]
  average_sessions_per_day: number
  typical_source_ips: string[]
  group_memberships: string[]
  privileged: boolean
  failed_logon_threshold: number
}

// ============================================================================
// ADVANCED CACHE TYPES
// ============================================================================

export interface CacheStatistics {
  hit_count: number
  miss_count: number
  hit_rate: number // 0.0 - 1.0
  total_size_bytes: number
  entry_count: number
  eviction_count: number
  warming_enabled: boolean
}

// ============================================================================
// TAURI COMMAND PARAMETER TYPES
// ============================================================================

// Audit Logging Commands
export interface LogAuditEventParams {
  category: AuditCategory
  severity: AuditSeverity
  action: string
  actor: string
  target?: string
  result: string
  domainId?: number
  domainName?: string
}

export interface QueryAuditLogsParams {
  startTime?: string
  endTime?: string
  category?: AuditCategory
  severity?: AuditSeverity
  domainId?: number
}

export interface GetAuditStatisticsParams {
  startTime?: string
  endTime?: string
  domainId?: number
}

export interface GenerateComplianceReportParams {
  standard: ComplianceStandard
  startTime: string
  endTime: string
}

// Risk Scoring Commands
export interface ScoreUserRiskParams {
  userDn: string
  username: string
  isPrivileged: boolean
  isEnabled: boolean
  lastLogon?: string
  passwordLastSet?: string
  privilegedGroups: string[]
  hasAdminRights: boolean
  failedLogonCount: number
  servicePrincipalNames: string[]
}

export interface ScoreDomainRiskParams {
  domainId?: number
  domainName: string
  krbtgtAgeDays: number
  adminCount: number
  staleAdminCount: number
  weakPasswordCount: number
  gpoIssuesCount: number
  delegationIssuesCount: number
  trustIssuesCount: number
  permissionIssuesCount: number
  previousScore?: number
}

// Anomaly Detection Commands
export interface BuildBaselineParams {
  entity: string
  entityType: EntityType
  logonHistory: LogonEvent[]
}

export interface DetectLogonAnomaliesParams {
  entity: string
  logonEvent: LogonEvent
}

export interface DetectPrivilegeEscalationParams {
  entity: string
  oldGroups: string[]
  newGroups: string[]
}

export interface DetectRapidLogonsParams {
  entity: string
  recentLogons: LogonEvent[]
  timeWindowMinutes: number
}

export interface GetBehavioralBaselineParams {
  entity: string
}
