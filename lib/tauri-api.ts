// Mock implementation for browser preview - in production, use actual Tauri invoke

// Environment detection: only use mock data in development/demo mode
const IS_DEMO_MODE = typeof window !== 'undefined' && !(window as any).__TAURI_INTERNALS__

export interface UserInfo {
  distinguished_name: string
  username: string
  email: string
  display_name: string
  enabled: boolean
  last_logon?: string
  groups: string[]
}

export interface ConnectionStatus {
  connected: boolean
  server: string
  username: string
  baseDn: string
  connectedAt: string
  useLdaps: boolean
}

export interface ValidationResult {
  valid: boolean
  error?: string
}

export interface Incident {
  id: string
  title: string
  description: string
  priority: "Critical" | "High" | "Medium" | "Low"
  status: "Open" | "Investigating" | "Contained" | "Resolved" | "Closed"
  created_at: string
  updated_at: string
  affected_systems: string[]
  actions: IncidentAction[]
  assigned_to?: string
}

export interface IncidentAction {
  id: string
  action_type: string
  description: string
  timestamp: string
  performed_by: string
}

// Mock data for demo purposes
const mockIncidents: Incident[] = [
  {
    id: "1",
    title: "Unauthorized Access Attempt",
    description: "Multiple failed login attempts detected from external IP",
    priority: "Critical",
    status: "Investigating",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    affected_systems: ["auth-server", "vpn-gateway"],
    actions: [
      {
        id: "a1",
        action_type: "Detection",
        description: "SIEM alert triggered for brute force attempt",
        timestamp: new Date().toISOString(),
        performed_by: "System",
      },
    ],
    assigned_to: "SOC Team",
  },
  {
    id: "2",
    title: "Suspicious File Download",
    description: "User downloaded potentially malicious attachment",
    priority: "High",
    status: "Open",
    created_at: new Date(Date.now() - 3600000).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
    affected_systems: ["workstation-142"],
    actions: [],
  },
  {
    id: "3",
    title: "Phishing Email Reported",
    description: "Employee reported suspicious email mimicking IT support",
    priority: "Medium",
    status: "Contained",
    created_at: new Date(Date.now() - 7200000).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
    affected_systems: ["email-gateway"],
    actions: [
      {
        id: "a2",
        action_type: "Containment",
        description: "Blocked sender domain at email gateway",
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        performed_by: "Admin",
      },
    ],
  },
]

// Check if running in Tauri environment (Tauri 2.x uses __TAURI_INTERNALS__)
const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window

async function invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (isTauri) {
    const { invoke: tauriInvoke } = await import("@tauri-apps/api/core")
    return tauriInvoke<T>(command, args)
  }
  throw new Error("Not in Tauri environment")
}

// Progress event types
export interface AuditProgressEvent {
  audit_type: string
  phase: string
  current: number
  total: number
  message: string
  items_found: number
}

export type UnlistenFn = () => void

/**
 * Listen for audit progress events from the Rust backend
 * @param callback Function to call when progress events are received
 * @returns A function to stop listening
 */
export async function listenToAuditProgress(
  callback: (event: AuditProgressEvent) => void
): Promise<UnlistenFn> {
  if (!isTauri) {
    // Return no-op unlisten function if not in Tauri
    return () => {}
  }

  const { listen } = await import("@tauri-apps/api/event")
  return await listen<AuditProgressEvent>("audit-progress", (event) => {
    callback(event.payload)
  })
}

export async function validateCredentials(
  server: string,
  username: string,
  password: string,
): Promise<ValidationResult> {
  return await invoke("validate_credentials", { server, username, password })
}

export async function purgeAllData(): Promise<string> {
  if (!isTauri) {
    return "Purge not available in browser mode"
  }
  return await invoke("purge_all_data")
}

export async function connectAD(server: string, username: string, password: string, baseDn: string): Promise<string> {
  return await invoke("connect_ad", { server, username, password, baseDn })
}

export async function searchUsers(searchQuery: string): Promise<UserInfo[]> {
  return await invoke("search_users", { searchQuery })
}

export async function disableUser(distinguishedName: string, reason: string): Promise<string> {
  return await invoke("disable_user", { distinguishedName, reason })
}

export async function getUserDetails(distinguishedName: string): Promise<UserInfo> {
  return await invoke("get_user_details", { distinguishedName })
}

export async function createIncident(
  title: string,
  description: string,
  priority: string,
  affectedSystems: string[],
): Promise<Incident> {
  return await invoke("create_incident", {
    title,
    description,
    priority,
    affectedSystems,
  })
}

export async function getIncidents(): Promise<Incident[]> {
  return await invoke("get_incidents")
}

export async function updateIncidentStatus(incidentId: string, status: string): Promise<Incident> {
  return await invoke("update_incident_status", { incidentId, status })
}

export async function addIncidentAction(
  incidentId: string,
  actionType: string,
  description: string,
): Promise<Incident> {
  return await invoke("add_incident_action", { incidentId, actionType, description })
}

// AdminSDHolder analysis types
export type RiskLevel = "Critical" | "High" | "Medium" | "Low" | "Info"

export type AceType =
  | "AccessAllowed"
  | "AccessDenied"
  | "AccessAllowedObject"
  | "AccessDeniedObject"
  | "SystemAudit"
  | "Unknown"

export interface AccessControlEntry {
  trustee: string
  trustee_sid: string
  access_mask: number
  ace_type: AceType
  ace_flags: number
  object_type?: string
  inherited_object_type?: string
  permissions: string[]
  risk_level: RiskLevel
  risk_reasons: string[]
}

export interface RiskSummary {
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  overall_risk: RiskLevel
  risk_score: number
}

export interface SecurityRecommendation {
  priority: RiskLevel
  title: string
  description: string
  affected_trustee?: string
  remediation_steps: string[]
}

export interface AdminSDHolderAnalysis {
  distinguished_name: string
  owner: string
  owner_sid: string
  group: string
  control_flags: number
  dacl_entries: AccessControlEntry[]
  sacl_entries: AccessControlEntry[]
  analysis_timestamp: string
  total_aces: number
  risky_aces: number
  risk_summary: RiskSummary
  recommendations: SecurityRecommendation[]
}

// Mock AdminSDHolder analysis data for demo
const mockAdminSDHolderAnalysis: AdminSDHolderAnalysis = {
  distinguished_name: "CN=AdminSDHolder,CN=System,DC=company,DC=com",
  owner: "Domain Admins",
  owner_sid: "S-1-5-21-1234567890-1234567890-1234567890-512",
  group: "Domain Admins",
  control_flags: 0x8004,
  dacl_entries: [
    {
      trustee: "BUILTIN\\Administrators",
      trustee_sid: "S-1-5-32-544",
      access_mask: 0x000f01ff,
      ace_type: "AccessAllowed",
      ace_flags: 0,
      permissions: ["GenericAll"],
      risk_level: "Info",
      risk_reasons: ["Expected permission for built-in Administrators"],
    },
    {
      trustee: "NT AUTHORITY\\SYSTEM",
      trustee_sid: "S-1-5-18",
      access_mask: 0x000f01ff,
      ace_type: "AccessAllowed",
      ace_flags: 0,
      permissions: ["GenericAll"],
      risk_level: "Info",
      risk_reasons: ["Expected permission for SYSTEM account"],
    },
    {
      trustee: "COMPANY\\Domain Admins",
      trustee_sid: "S-1-5-21-1234567890-1234567890-1234567890-512",
      access_mask: 0x000f01ff,
      ace_type: "AccessAllowed",
      ace_flags: 0,
      permissions: ["GenericAll"],
      risk_level: "Info",
      risk_reasons: ["Expected permission for Domain Admins"],
    },
    {
      trustee: "COMPANY\\Enterprise Admins",
      trustee_sid: "S-1-5-21-1234567890-1234567890-1234567890-519",
      access_mask: 0x000f01ff,
      ace_type: "AccessAllowed",
      ace_flags: 0,
      permissions: ["GenericAll"],
      risk_level: "Info",
      risk_reasons: ["Expected permission for Enterprise Admins"],
    },
    {
      trustee: "COMPANY\\IT-HelpDesk",
      trustee_sid: "S-1-5-21-1234567890-1234567890-1234567890-1337",
      access_mask: 0x10000000,
      ace_type: "AccessAllowed",
      ace_flags: 0,
      permissions: ["WriteDacl"],
      risk_level: "Critical",
      risk_reasons: [
        "WriteDacl: Can modify permissions - could grant themselves full control",
        "Non-administrative group has permission modification rights",
      ],
    },
    {
      trustee: "COMPANY\\ServiceAccount-Backup",
      trustee_sid: "S-1-5-21-1234567890-1234567890-1234567890-2001",
      access_mask: 0x000f01ff,
      ace_type: "AccessAllowed",
      ace_flags: 0,
      permissions: ["GenericAll"],
      risk_level: "Critical",
      risk_reasons: [
        "GenericAll: Full control over object - can modify any attribute or take ownership",
        "Service account has excessive permissions on AdminSDHolder",
      ],
    },
    {
      trustee: "NT AUTHORITY\\Authenticated Users",
      trustee_sid: "S-1-5-11",
      access_mask: 0x00000020,
      ace_type: "AccessAllowed",
      ace_flags: 0,
      object_type: "00299570-246d-11d0-a768-00aa006e0529",
      permissions: ["WriteProperty", "User-Force-Change-Password"],
      risk_level: "Critical",
      risk_reasons: [
        "Authenticated Users: Any authenticated user could exploit these permissions",
        "Extended right 'User-Force-Change-Password' could enable privilege escalation",
      ],
    },
    {
      trustee: "BUILTIN\\Account Operators",
      trustee_sid: "S-1-5-32-548",
      access_mask: 0x00000020,
      ace_type: "AccessAllowed",
      ace_flags: 0,
      permissions: ["WriteProperty"],
      risk_level: "High",
      risk_reasons: [
        "Account Operators: Should not have permissions on AdminSDHolder",
        "WriteProperty: Can modify properties - depends on which properties",
      ],
    },
  ],
  sacl_entries: [],
  analysis_timestamp: new Date().toISOString(),
  total_aces: 8,
  risky_aces: 4,
  risk_summary: {
    critical_count: 3,
    high_count: 1,
    medium_count: 0,
    low_count: 0,
    overall_risk: "Critical",
    risk_score: 140,
  },
  recommendations: [
    {
      priority: "Critical",
      title: "Remove Full Control Permission",
      description:
        "The trustee 'COMPANY\\ServiceAccount-Backup' has Full Control (GenericAll) on AdminSDHolder. This permission will propagate to all protected accounts.",
      affected_trustee: "COMPANY\\ServiceAccount-Backup",
      remediation_steps: [
        "Review if this trustee requires administrative access",
        "If not required, remove the ACE from AdminSDHolder",
        "Wait for SDProp to propagate changes (default: 60 minutes)",
        "Verify changes on protected accounts",
      ],
    },
    {
      priority: "Critical",
      title: "Remove Permission Modification Rights",
      description:
        "The trustee 'COMPANY\\IT-HelpDesk' can modify permissions or ownership. This could be exploited to grant full access to protected accounts.",
      affected_trustee: "COMPANY\\IT-HelpDesk",
      remediation_steps: [
        "Remove WriteDacl and WriteOwner permissions",
        "Audit who made this change and when",
        "Review security logs for suspicious activity",
      ],
    },
    {
      priority: "Critical",
      title: "Remove Password Reset Rights from Authenticated Users",
      description:
        "Authenticated Users can force password changes on protected accounts. This is a critical privilege escalation vector.",
      affected_trustee: "NT AUTHORITY\\Authenticated Users",
      remediation_steps: [
        "Immediately remove User-Force-Change-Password extended right",
        "Investigate how this permission was added",
        "Audit for any unauthorized password resets",
        "Review protected accounts for signs of compromise",
      ],
    },
    {
      priority: "High",
      title: "Remove Account Operators Permissions",
      description: "Account Operators should not have permissions on AdminSDHolder per security best practices.",
      affected_trustee: "BUILTIN\\Account Operators",
      remediation_steps: [
        "Remove all ACEs for Account Operators from AdminSDHolder",
        "Review if Account Operators need any delegated permissions elsewhere",
      ],
    },
  ],
}

// AdminSDHolder analysis function
export async function analyzeAdminSDHolder(): Promise<AdminSDHolderAnalysis> {
  return await invoke("analyze_adminsdholder")
}

// Function to get only risky ACEs
export async function getAdminSDHolderRiskyAces(): Promise<AccessControlEntry[]> {
  return await invoke("get_adminsdholder_risky_aces")
}

// KRBTGT analysis types
export type KrbtgtRiskLevel = "Critical" | "High" | "Medium" | "Low" | "Healthy"
export type AgeStatus = "Healthy" | "Approaching" | "Overdue" | "Critical"

export interface KrbtgtAccountInfo {
  distinguished_name: string
  sam_account_name: string
  domain: string
  created: string
  last_password_change: string
  password_age_days: number
  account_status: {
    is_enabled: boolean
    is_locked: boolean
    password_never_expires: boolean
  }
  key_version_number: number
  last_rotation_info?: RotationInfo
}

export interface RotationInfo {
  first_rotation_time?: string
  second_rotation_time?: string
  rotation_complete: boolean
  performed_by?: string
}

export interface KrbtgtAgeAnalysis {
  account_info: KrbtgtAccountInfo
  age_days: number
  recommended_max_age_days: number
  is_overdue: boolean
  risk_level: KrbtgtRiskLevel
  age_status: AgeStatus
  recommendations: KrbtgtRecommendation[]
  analysis_timestamp: string
}

export interface KrbtgtRecommendation {
  priority: KrbtgtRiskLevel
  title: string
  description: string
  action_required: boolean
}

export interface RotationStatus {
  rotation_in_progress: boolean
  first_rotation_complete: boolean
  second_rotation_complete: boolean
  first_rotation_time?: string
  second_rotation_time?: string
  time_since_first_rotation?: number
  ready_for_second_rotation: boolean
  minimum_wait_hours: number
  recommended_wait_hours: number
}

export interface RotationResult {
  success: boolean
  rotation_number: number
  new_key_version: number
  timestamp: string
  message: string
  next_steps: string[]
  wait_time_recommendation?: string
}

const mockKrbtgtAnalysis: KrbtgtAgeAnalysis = {
  account_info: {
    distinguished_name: "CN=krbtgt,CN=Users,DC=company,DC=com",
    sam_account_name: "krbtgt",
    domain: "company.com",
    created: "2020-01-15T10:30:00Z",
    last_password_change: new Date(Date.now() - 200 * 24 * 60 * 60 * 1000).toISOString(),
    password_age_days: 200,
    account_status: {
      is_enabled: false, // KRBTGT is always disabled
      is_locked: false,
      password_never_expires: true,
    },
    key_version_number: 4,
  },
  age_days: 200,
  recommended_max_age_days: 180,
  is_overdue: true,
  risk_level: "High",
  age_status: "Overdue",
  recommendations: [
    {
      priority: "High",
      title: "KRBTGT Rotation Recommended",
      description:
        "The KRBTGT password is 200 days old, exceeding the recommended maximum of 180 days. Schedule a rotation during a maintenance window.",
      action_required: true,
    },
    {
      priority: "Low",
      title: "Remember: Two Rotations Required",
      description:
        "KRBTGT rotation must be performed twice to fully invalidate existing tickets. Wait at least 10 hours (maximum TGT lifetime) between rotations.",
      action_required: false,
    },
  ],
  analysis_timestamp: new Date().toISOString(),
}

let mockRotationStatus: RotationStatus = {
  rotation_in_progress: false,
  first_rotation_complete: false,
  second_rotation_complete: false,
  first_rotation_time: undefined,
  second_rotation_time: undefined,
  time_since_first_rotation: undefined,
  ready_for_second_rotation: false,
  minimum_wait_hours: 10,
  recommended_wait_hours: 24,
}

// KRBTGT analysis function
/**
 * @deprecated Use auditKrbtgt() instead for consistency with other audit functions
 * Both functions call the same Rust command, kept for backwards compatibility
 */
export async function analyzeKrbtgt(): Promise<KrbtgtAgeAnalysis> {
  return await invoke("analyze_krbtgt")
}

// KRBTGT rotation function
export async function rotateKrbtgt(
  rotationNumber: number,
  confirmUnderstanding: boolean,
  reason: string,
): Promise<RotationResult> {
  return await invoke("rotate_krbtgt", {
    rotationNumber,
    confirmUnderstanding,
    reason,
  })
}

// Get rotation status function
export async function getKrbtgtRotationStatus(): Promise<RotationStatus> {
  return await invoke("get_krbtgt_rotation_status")
}

// Reset rotation status function
export async function resetKrbtgtRotationStatus(): Promise<void> {
  await invoke("reset_krbtgt_rotation_status")
}

// Privileged account types
export type PrivilegeLevel = "Tier0" | "Tier1" | "Tier2" | "Delegated" | "Service"
export type AccountType =
  | "User"
  | "ServiceAccount"
  | "ManagedServiceAccount"
  | "GroupManagedServiceAccount"
  | "Computer"
export type PrivilegeSourceType =
  | "GroupMembership"
  | "AclPermission"
  | "DelegatedPermission"
  | "ServicePrincipal"
  | "AdminCount"
export type RiskFactorType =
  | "PasswordNeverExpires"
  | "StalePassword"
  | "NoRecentLogon"
  | "ExcessivePrivileges"
  | "ServiceAccountAsAdmin"
  | "NestedPrivileges"
  | "UnconstainedDelegation"
  | "KerberoastableSpn"
  | "NotProtected"
  | "PasswordNotRequired"
  | "DisabledWithPrivileges"

export type PrivilegedGroupType =
  | "DomainAdmins"
  | "EnterpriseAdmins"
  | "SchemaAdmins"
  | "Administrators"
  | "AccountOperators"
  | "BackupOperators"
  | "ServerOperators"
  | "PrintOperators"
  | "DnsAdmins"
  | "GroupPolicyCreatorOwners"
  | "CryptoOperators"
  | "RemoteDesktopUsers"
  | "HyperVAdministrators"
  | "AccessControlAssistanceOperators"

export interface PrivilegeSource {
  source_type: PrivilegeSourceType
  source_name: string
  source_dn?: string
  privilege_level: PrivilegeLevel
  is_direct: boolean
  nested_path?: string[]
}

export interface RiskFactor {
  factor_type: RiskFactorType
  description: string
  severity: "Critical" | "High" | "Medium" | "Low"
  score_impact: number
}

export interface PrivilegedAccount {
  distinguished_name: string
  sam_account_name: string
  display_name: string
  email?: string
  is_enabled: boolean
  is_locked: boolean
  last_logon?: string
  password_last_set?: string
  password_never_expires: boolean
  account_type: AccountType
  privilege_sources: PrivilegeSource[]
  highest_privilege_level: PrivilegeLevel
  total_risk_score: number
  risk_factors: RiskFactor[]
  is_sensitive: boolean
  is_protected: boolean
}

export interface PrivilegedGroup {
  name: string
  distinguished_name: string
  sid: string
  group_type: PrivilegedGroupType
  privilege_level: PrivilegeLevel
  member_count: number
  description: string
  risk_score: number
  is_protected: boolean
}

export interface PrivilegedAccountRecommendation {
  priority: "Critical" | "High" | "Medium" | "Low"
  category: string
  title: string
  description: string
  affected_count: number
  remediation_steps: string[]
}

export interface PrivilegedAccountSummary {
  total_privileged_accounts: number
  total_tier0_accounts: number
  total_tier1_accounts: number
  total_tier2_accounts: number
  total_delegated_accounts: number
  total_service_accounts: number
  enabled_accounts: number
  disabled_accounts: number
  locked_accounts: number
  high_risk_accounts: number
  accounts_with_stale_passwords: number
  accounts_password_never_expires: number
  kerberoastable_accounts: number
  privileged_groups: PrivilegedGroup[]
  accounts_by_group: Record<string, number>
  overall_risk_score: number
  risk_level: "Critical" | "High" | "Medium" | "Low"
  analysis_timestamp: string
  recommendations: PrivilegedAccountRecommendation[]
}

const mockPrivilegedGroups: PrivilegedGroup[] = [
  {
    name: "Domain Admins",
    distinguished_name: "CN=Domain Admins,CN=Users,DC=company,DC=com",
    sid: "S-1-5-21-1234567890-1234567890-1234567890-512",
    group_type: "DomainAdmins",
    privilege_level: "Tier0",
    member_count: 8,
    description: "Designated administrators of the domain",
    risk_score: 100,
    is_protected: true,
  },
  {
    name: "Enterprise Admins",
    distinguished_name: "CN=Enterprise Admins,CN=Users,DC=company,DC=com",
    sid: "S-1-5-21-1234567890-1234567890-1234567890-519",
    group_type: "EnterpriseAdmins",
    privilege_level: "Tier0",
    member_count: 3,
    description: "Designated administrators of the enterprise",
    risk_score: 100,
    is_protected: true,
  },
  {
    name: "Schema Admins",
    distinguished_name: "CN=Schema Admins,CN=Users,DC=company,DC=com",
    sid: "S-1-5-21-1234567890-1234567890-1234567890-518",
    group_type: "SchemaAdmins",
    privilege_level: "Tier0",
    member_count: 2,
    description: "Designated administrators of the schema",
    risk_score: 100,
    is_protected: true,
  },
  {
    name: "Administrators",
    distinguished_name: "CN=Administrators,CN=Builtin,DC=company,DC=com",
    sid: "S-1-5-32-544",
    group_type: "Administrators",
    privilege_level: "Tier0",
    member_count: 12,
    description: "Built-in Administrators group",
    risk_score: 90,
    is_protected: true,
  },
  {
    name: "Account Operators",
    distinguished_name: "CN=Account Operators,CN=Builtin,DC=company,DC=com",
    sid: "S-1-5-32-548",
    group_type: "AccountOperators",
    privilege_level: "Tier1",
    member_count: 4,
    description: "Members can administer domain user and group accounts",
    risk_score: 70,
    is_protected: true,
  },
  {
    name: "Backup Operators",
    distinguished_name: "CN=Backup Operators,CN=Builtin,DC=company,DC=com",
    sid: "S-1-5-32-551",
    group_type: "BackupOperators",
    privilege_level: "Tier1",
    member_count: 3,
    description: "Members can backup and restore files regardless of permissions",
    risk_score: 70,
    is_protected: true,
  },
  {
    name: "DnsAdmins",
    distinguished_name: "CN=DnsAdmins,CN=Users,DC=company,DC=com",
    sid: "S-1-5-21-1234567890-1234567890-1234567890-1101",
    group_type: "DnsAdmins",
    privilege_level: "Tier1",
    member_count: 5,
    description: "DNS Administrators Group",
    risk_score: 80,
    is_protected: false,
  },
  {
    name: "Server Operators",
    distinguished_name: "CN=Server Operators,CN=Builtin,DC=company,DC=com",
    sid: "S-1-5-32-549",
    group_type: "ServerOperators",
    privilege_level: "Tier1",
    member_count: 2,
    description: "Members can administer domain servers",
    risk_score: 60,
    is_protected: true,
  },
]

const mockPrivilegedAccounts: PrivilegedAccount[] = [
  {
    distinguished_name: "CN=Administrator,CN=Users,DC=company,DC=com",
    sam_account_name: "Administrator",
    display_name: "Built-in Administrator",
    email: undefined,
    is_enabled: true,
    is_locked: false,
    last_logon: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    password_last_set: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
    password_never_expires: true,
    account_type: "User",
    privilege_sources: [
      { source_type: "GroupMembership", source_name: "Domain Admins", privilege_level: "Tier0", is_direct: true },
      { source_type: "GroupMembership", source_name: "Enterprise Admins", privilege_level: "Tier0", is_direct: true },
      { source_type: "GroupMembership", source_name: "Schema Admins", privilege_level: "Tier0", is_direct: true },
    ],
    highest_privilege_level: "Tier0",
    total_risk_score: 45,
    risk_factors: [
      {
        factor_type: "PasswordNeverExpires",
        description: "Password is set to never expire",
        severity: "High",
        score_impact: 25,
      },
      {
        factor_type: "ExcessivePrivileges",
        description: "Member of 3 Tier 0 privileged groups",
        severity: "High",
        score_impact: 20,
      },
    ],
    is_sensitive: true,
    is_protected: true,
  },
  {
    distinguished_name: "CN=John Smith,OU=IT,DC=company,DC=com",
    sam_account_name: "jsmith",
    display_name: "John Smith",
    email: "jsmith@company.com",
    is_enabled: true,
    is_locked: false,
    last_logon: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
    password_last_set: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    password_never_expires: false,
    account_type: "User",
    privilege_sources: [
      { source_type: "GroupMembership", source_name: "Domain Admins", privilege_level: "Tier0", is_direct: true },
    ],
    highest_privilege_level: "Tier0",
    total_risk_score: 10,
    risk_factors: [],
    is_sensitive: false,
    is_protected: true,
  },
  {
    distinguished_name: "CN=svc-backup,OU=Service Accounts,DC=company,DC=com",
    sam_account_name: "svc-backup",
    display_name: "Backup Service Account",
    email: undefined,
    is_enabled: true,
    is_locked: false,
    last_logon: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
    password_last_set: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString(),
    password_never_expires: true,
    account_type: "ServiceAccount",
    privilege_sources: [
      { source_type: "GroupMembership", source_name: "Backup Operators", privilege_level: "Tier1", is_direct: true },
      {
        source_type: "GroupMembership",
        source_name: "Domain Admins",
        privilege_level: "Tier0",
        is_direct: false,
        nested_path: ["IT-Admins", "Domain Admins"],
      },
    ],
    highest_privilege_level: "Tier0",
    total_risk_score: 85,
    risk_factors: [
      {
        factor_type: "PasswordNeverExpires",
        description: "Password is set to never expire",
        severity: "High",
        score_impact: 25,
      },
      {
        factor_type: "ServiceAccountAsAdmin",
        description: "Service account has administrative privileges",
        severity: "High",
        score_impact: 30,
      },
      {
        factor_type: "StalePassword",
        description: "Password has not been changed in over 365 days",
        severity: "Critical",
        score_impact: 30,
      },
    ],
    is_sensitive: false,
    is_protected: true,
  },
  {
    distinguished_name: "CN=Jane Doe,OU=IT,DC=company,DC=com",
    sam_account_name: "jdoe",
    display_name: "Jane Doe",
    email: "jdoe@company.com",
    is_enabled: true,
    is_locked: false,
    last_logon: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
    password_last_set: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(),
    password_never_expires: false,
    account_type: "User",
    privilege_sources: [
      { source_type: "GroupMembership", source_name: "Account Operators", privilege_level: "Tier1", is_direct: true },
      { source_type: "GroupMembership", source_name: "DnsAdmins", privilege_level: "Tier1", is_direct: true },
    ],
    highest_privilege_level: "Tier1",
    total_risk_score: 15,
    risk_factors: [],
    is_sensitive: false,
    is_protected: true,
  },
  {
    distinguished_name: "CN=svc-sql,OU=Service Accounts,DC=company,DC=com",
    sam_account_name: "svc-sql",
    display_name: "SQL Service Account",
    email: undefined,
    is_enabled: true,
    is_locked: false,
    last_logon: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
    password_last_set: new Date(Date.now() - 200 * 24 * 60 * 60 * 1000).toISOString(),
    password_never_expires: true,
    account_type: "ServiceAccount",
    privilege_sources: [
      { source_type: "GroupMembership", source_name: "Administrators", privilege_level: "Tier0", is_direct: true },
    ],
    highest_privilege_level: "Tier0",
    total_risk_score: 70,
    risk_factors: [
      {
        factor_type: "PasswordNeverExpires",
        description: "Password is set to never expire",
        severity: "High",
        score_impact: 25,
      },
      {
        factor_type: "ServiceAccountAsAdmin",
        description: "Service account has administrative privileges",
        severity: "High",
        score_impact: 30,
      },
      {
        factor_type: "KerberoastableSpn",
        description: "Account has SPN set and is vulnerable to Kerberoasting",
        severity: "Critical",
        score_impact: 35,
      },
    ],
    is_sensitive: false,
    is_protected: true,
  },
  {
    distinguished_name: "CN=Bob Wilson,OU=IT,DC=company,DC=com",
    sam_account_name: "bwilson",
    display_name: "Bob Wilson",
    email: "bwilson@company.com",
    is_enabled: false,
    is_locked: false,
    last_logon: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(),
    password_last_set: new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString(),
    password_never_expires: false,
    account_type: "User",
    privilege_sources: [
      { source_type: "GroupMembership", source_name: "Domain Admins", privilege_level: "Tier0", is_direct: true },
    ],
    highest_privilege_level: "Tier0",
    total_risk_score: 35,
    risk_factors: [
      {
        factor_type: "DisabledWithPrivileges",
        description: "Disabled account still has privileged group memberships",
        severity: "Medium",
        score_impact: 15,
      },
      { factor_type: "NoRecentLogon", description: "No logon in over 30 days", severity: "Medium", score_impact: 10 },
    ],
    is_sensitive: false,
    is_protected: true,
  },
  {
    distinguished_name: "CN=Sarah Johnson,OU=IT,DC=company,DC=com",
    sam_account_name: "sjohnson",
    display_name: "Sarah Johnson",
    email: "sjohnson@company.com",
    is_enabled: true,
    is_locked: false,
    last_logon: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    password_last_set: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
    password_never_expires: false,
    account_type: "User",
    privilege_sources: [
      { source_type: "GroupMembership", source_name: "Server Operators", privilege_level: "Tier1", is_direct: true },
    ],
    highest_privilege_level: "Tier1",
    total_risk_score: 5,
    risk_factors: [],
    is_sensitive: false,
    is_protected: true,
  },
]

const mockPrivilegedSummary: PrivilegedAccountSummary = {
  total_privileged_accounts: 18,
  total_tier0_accounts: 8,
  total_tier1_accounts: 7,
  total_tier2_accounts: 3,
  total_delegated_accounts: 2,
  total_service_accounts: 4,
  enabled_accounts: 16,
  disabled_accounts: 2,
  locked_accounts: 0,
  high_risk_accounts: 3,
  accounts_with_stale_passwords: 2,
  accounts_password_never_expires: 5,
  kerberoastable_accounts: 2,
  privileged_groups: mockPrivilegedGroups,
  accounts_by_group: {
    "Domain Admins": 8,
    "Enterprise Admins": 3,
    "Schema Admins": 2,
    Administrators: 12,
    "Account Operators": 4,
    "Backup Operators": 3,
    DnsAdmins: 5,
    "Server Operators": 2,
  },
  overall_risk_score: 62,
  risk_level: "High",
  analysis_timestamp: new Date().toISOString(),
  recommendations: [
    {
      priority: "High",
      category: "Account Governance",
      title: "Reduce Tier 0 Account Count",
      description: "You have 8 Tier 0 accounts. Microsoft recommends limiting Domain Admins to 5 or fewer.",
      affected_count: 8,
      remediation_steps: [
        "Audit all Tier 0 accounts and their business justification",
        "Remove accounts that don't require permanent admin access",
        "Implement just-in-time (JIT) privileged access",
        "Use Privileged Access Workstations (PAWs) for admin tasks",
      ],
    },
    {
      priority: "High",
      category: "Password Security",
      title: "Enable Password Expiration",
      description: "5 privileged accounts have 'Password never expires' set.",
      affected_count: 5,
      remediation_steps: [
        "Review each account to determine if flag is necessary",
        "For service accounts, implement managed service accounts (gMSA)",
        "Remove flag from user accounts and enforce password policies",
        "Document exceptions with business justification",
      ],
    },
    {
      priority: "Critical",
      category: "Kerberos Security",
      title: "Address Kerberoastable Privileged Accounts",
      description: "2 privileged accounts have SPNs that can be Kerberoasted.",
      affected_count: 2,
      remediation_steps: [
        "Migrate service accounts to gMSA where possible",
        "Use long, complex passwords (25+ characters) for legacy SPNs",
        "Enable AES encryption and disable RC4 for Kerberos",
        "Monitor for Kerberoasting attempts in security logs",
      ],
    },
    {
      priority: "High",
      category: "Service Account Security",
      title: "Review Service Accounts with Admin Privileges",
      description: "2 service accounts have Tier 0 administrative privileges.",
      affected_count: 2,
      remediation_steps: [
        "Audit service accounts for minimum required permissions",
        "Remove from Domain Admins and use delegated permissions",
        "Convert to Group Managed Service Accounts (gMSA)",
        "Implement credential tiering and isolation",
      ],
    },
    {
      priority: "Medium",
      category: "Account Cleanup",
      title: "Remove Disabled Accounts from Privileged Groups",
      description: "1 disabled account still has privileged group memberships.",
      affected_count: 1,
      remediation_steps: [
        "Remove disabled accounts from all privileged groups",
        "Document reason for account disablement",
        "Consider deleting accounts after retention period",
      ],
    },
  ],
}

// Privileged account API functions
export async function enumeratePrivilegedAccounts(): Promise<PrivilegedAccount[]> {
  return await invoke("enumerate_privileged_accounts")
}

/**
 * @deprecated Use auditPrivilegedAccounts() instead for consistency with other audit functions
 * Both functions call the same Rust command, kept for backwards compatibility
 */
export async function getPrivilegedAccountSummary(): Promise<PrivilegedAccountSummary> {
  return await invoke("get_privileged_account_summary")
}

export async function getPrivilegedGroups(): Promise<PrivilegedGroup[]> {
  return await invoke("get_privileged_groups")
}

// ==========================================
// Domain Security Audit Types
// ==========================================

export type FindingCategory =
  | "DomainSecurity"
  | "PasswordPolicy"
  | "FunctionalLevel"
  | "LegacySystems"
  | "AzureADSSO"
  | "RecycleBin"
  | "GroupPolicy"
  | "SysvolPermissions"

export type FindingSeverity = "Critical" | "High" | "Medium" | "Low" | "Informational"

export interface SecurityFinding {
  id: string
  category: FindingCategory
  issue: string
  severity: FindingSeverity
  severity_level: number
  affected_object: string
  description: string
  impact: string
  remediation: string
  details: Record<string, unknown>
}

export interface PasswordPolicyInfo {
  min_password_length: number
  password_history_count: number
  max_password_age_days: number
  min_password_age_days: number
  complexity_enabled: boolean
  reversible_encryption_enabled: boolean
  lockout_threshold: number
  lockout_duration_minutes: number
  lockout_observation_window_minutes: number
}

export interface LegacyComputer {
  name: string
  distinguished_name: string
  operating_system: string
  operating_system_version?: string
  last_logon?: string
  is_enabled: boolean
}

export interface AzureSsoAccountStatus {
  sam_account_name: string
  distinguished_name: string
  password_last_set?: string
  password_age_days?: number
  is_enabled: boolean
  needs_rotation: boolean
}

export interface OptionalFeatureStatus {
  name: string
  is_enabled: boolean
  enabled_scopes: string[]
}

export interface DomainSecurityAudit {
  domain_name: string
  domain_dns_root: string
  domain_functional_level: string
  forest_functional_level: string
  password_policy: PasswordPolicyInfo
  recycle_bin_enabled: boolean
  optional_features: OptionalFeatureStatus[]
  legacy_computers: LegacyComputer[]
  azure_sso_accounts: AzureSsoAccountStatus[]
  findings: SecurityFinding[]
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  overall_risk_score: number
  risk_level: string
  audit_timestamp: string
}

// ==========================================
// GPO Audit Types
// ==========================================

export type GpoPermissionLevel = "GpoApply" | "GpoRead" | "GpoEdit" | "GpoEditDeleteModifySecurity" | "GpoCustom"

export interface GpoPermissionEntry {
  trustee: string
  trustee_type: string
  permission: GpoPermissionLevel
  permission_name: string
  inherited: boolean
}

export interface GpoLink {
  ou_name: string
  ou_distinguished_name: string
  link_enabled: boolean
  enforced: boolean
  link_order: number
}

export interface GroupPolicyObject {
  id: string
  display_name: string
  path: string
  created_time?: string
  modified_time?: string
  owner: string
  permissions: GpoPermissionEntry[]
  links: GpoLink[]
  computer_settings_enabled: boolean
  user_settings_enabled: boolean
  wmi_filter?: string
}

export interface SysvolPermission {
  identity: string
  access_type: string
  rights: string
  inherited: boolean
  is_dangerous: boolean
}

export interface GpoAuditSummary {
  total_gpos: number
  gpos_with_dangerous_permissions: number
  gpos_linked_to_dc_ou: number
  unlinked_gpos: number
  gpos_with_weak_dc_permissions: number
  sysvol_permission_issues: number
}

export interface GpoAudit {
  domain_name: string
  sysvol_path: string
  gpos: GroupPolicyObject[]
  sysvol_permissions: SysvolPermission[]
  findings: SecurityFinding[]
  summary: GpoAuditSummary
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  overall_risk_score: number
  risk_level: string
  audit_timestamp: string
}

// ==========================================
// Delegation Audit Types
// ==========================================

export type DelegationType = "Unconstrained" | "Constrained" | "ConstrainedWithProtocolTransition" | "ResourceBased"
export type DelegationAccountType = "User" | "Computer" | "ManagedServiceAccount" | "GroupManagedServiceAccount"

export interface DelegationEntry {
  sam_account_name: string
  distinguished_name: string
  account_type: DelegationAccountType
  delegation_type: DelegationType
  enabled: boolean
  allowed_to_delegate_to: string[]
  trusted_for_delegation: boolean
  trusted_to_auth_for_delegation: boolean
  service_principal_names: string[]
  principals_allowed_to_delegate: string[]
}

export interface DelegationDetails {
  distinguished_name: string
  allowed_to_delegate_to: string[]
  trusted_to_auth_for_delegation: boolean
  enabled: boolean
  service_principal_names: string[]
  principals_allowed_to_delegate: string[]
}

export interface DelegationFinding {
  category: string
  issue: string
  severity: string
  severity_level: number
  affected_object: string
  account_type: DelegationAccountType
  delegation_type: DelegationType
  description: string
  impact: string
  remediation: string
  details: DelegationDetails
}

export interface DelegationRecommendation {
  priority: number
  title: string
  description: string
  steps: string[]
}

export interface DelegationAudit {
  total_delegations: number
  unconstrained_count: number
  constrained_count: number
  protocol_transition_count: number
  rbcd_count: number
  user_account_delegations: number
  computer_account_delegations: number
  findings: DelegationFinding[]
  delegations: DelegationEntry[]
  risk_score: number
  scan_timestamp: string
  recommendations: DelegationRecommendation[]
}

// ==========================================
// Domain Trust Audit Types
// ==========================================

export type TrustDirection = "Inbound" | "Outbound" | "Bidirectional"
export type TrustType = "External" | "Forest" | "ParentChild" | "TreeRoot" | "Shortcut" | "Realm"

export interface DomainTrust {
  target_domain: string
  source_domain: string
  direction: TrustDirection
  trust_type: TrustType
  sid_filtering_enabled: boolean
  selective_authentication: boolean
  is_transitive: boolean
  created: string
  modified: string
  trust_attributes: number
}

export interface TrustDetails {
  target: string
  direction: string
  trust_type: string
  sid_filtering_quarantined?: boolean
  selective_authentication?: boolean
  created?: string
  last_modified?: string
  days_since_modified?: number
}

export interface TrustFinding {
  category: string
  issue: string
  severity: string
  severity_level: number
  affected_object: string
  description: string
  impact: string
  remediation: string
  details: TrustDetails
}

export interface TrustRecommendation {
  priority: number
  title: string
  description: string
  command: string
  steps: string[]
}

export interface DomainTrustAudit {
  total_trusts: number
  inbound_trusts: number
  outbound_trusts: number
  bidirectional_trusts: number
  forest_trusts: number
  external_trusts: number
  trusts_without_sid_filtering: number
  trusts_without_selective_auth: number
  trusts: DomainTrust[]
  findings: TrustFinding[]
  risk_score: number
  scan_timestamp: string
  recommendations: TrustRecommendation[]
}

// ==========================================
// Permissions Audit Types
// ==========================================

export interface PermissionEntry {
  identity_reference: string
  identity_sid: string
  object_dn: string
  object_type_name: string
  active_directory_rights: string
  access_control_type: string
  object_type_guid: string
  inherited_object_type_guid: string
  is_inherited: boolean
  inheritance_flags: string
  propagation_flags: string
}

export interface PermissionDetails {
  object_dn: string
  identity: string
  identity_sid: string
  active_directory_rights: string
  access_control_type: string
  object_type: string
  is_inherited: boolean
  expected_rights?: string
}

export interface PermissionFinding {
  category: string
  issue: string
  severity: string
  severity_level: number
  affected_object: string
  description: string
  impact: string
  remediation: string
  details: PermissionDetails
}

export interface EnterpriseKeyAdminsAnalysis {
  exists: boolean
  group_dn?: string
  member_count: number
  has_excessive_rights: boolean
  has_dcsync_capability: boolean
  permissions: PermissionEntry[]
  findings: PermissionFinding[]
}

export interface CriticalOuAnalysis {
  ou_dn: string
  ou_name: string
  dangerous_permissions: PermissionEntry[]
  findings: PermissionFinding[]
}

export interface PermissionRecommendation {
  priority: number
  title: string
  description: string
  steps: string[]
}

export interface PermissionsAudit {
  total_dangerous_permissions: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  enterprise_key_admins: EnterpriseKeyAdminsAnalysis
  critical_ous: CriticalOuAnalysis[]
  all_findings: PermissionFinding[]
  risk_score: number
  scan_timestamp: string
  recommendations: PermissionRecommendation[]
}

// ==========================================
// Group Audit Types
// ==========================================

export interface GroupMember {
  sam_account_name: string
  distinguished_name: string
  object_class: string
  enabled: boolean | null
  last_logon: string | null
}

export interface PrivilegedGroupInfo {
  name: string
  distinguished_name: string
  member_count: number
  threshold: number
  is_critical: boolean
  nested_groups: GroupMember[]
  disabled_users: GroupMember[]
  inactive_users: GroupMember[]
  all_members: GroupMember[]
}

export interface GroupFindingDetails {
  group_dn?: string
  member_count?: number
  threshold?: number
  members?: string[]
  nested_groups?: string[]
  user_dn?: string
  last_logon?: string
}

export interface GroupFinding {
  category: string
  issue: string
  severity: string
  severity_level: number
  affected_object: string
  description: string
  impact: string
  remediation: string
  details: GroupFindingDetails
}

export interface GroupRecommendation {
  priority: number
  title: string
  description: string
  steps: string[]
}

export interface GroupAudit {
  total_groups_scanned: number
  groups_with_issues: number
  excessive_membership_count: number
  nested_groups_count: number
  disabled_users_count: number
  inactive_users_count: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  groups: PrivilegedGroupInfo[]
  findings: GroupFinding[]
  risk_score: number
  scan_timestamp: string
  recommendations: GroupRecommendation[]
}

// ==========================================
// DA Equivalence Audit Types
// ==========================================

export interface EquivalenceEvidence {
  reason: string
  target: string
  attack_path?: string
  rights?: string
  distinguished_name?: string
  additional_context?: string
}

export interface EquivalentPrincipal {
  principal: string
  evidence: EquivalenceEvidence[]
  is_critical: boolean
  total_paths: number
}

export interface ShadowCredentialWriteAccess {
  principal: string
  target_name: string
  target_dn: string
  target_type: string
  rights: string
}

export interface WriteSPNVulnerability {
  principal: string
  target_account: string
  target_dn: string
  rights: string
}

export interface UnconstrainedDelegation {
  account_name: string
  distinguished_name: string
  account_type: string
  operating_system?: string
  spns: string[]
  is_domain_controller: boolean
}

export interface RBCDWriteAccess {
  principal: string
  target_name: string
  target_dn: string
  is_domain_controller: boolean
}

export interface DNSZoneControl {
  principal: string
  zone_name: string
  zone_dn: string
  rights: string
}

export interface GPOLinkRights {
  principal: string
  target: string
  target_dn: string
  rights: string
}

export interface ExchangePrivExchange {
  principal: string
  group_name: string
  has_writedacl: boolean
}

export interface PrivilegedAccountTakeover {
  principal: string
  target_account: string
  target_dn: string
  rights: string
  can_reset_password: boolean
}

export interface GroupMembershipControl {
  principal: string
  group_name: string
  group_dn: string
  rights: string
  is_add_member_right: boolean
}

export interface OUControl {
  principal: string
  ou_name: string
  ou_dn: string
  rights: string
  contains_privileged_objects: boolean
}

export interface ComputerObjectControl {
  principal: string
  computer_name: string
  computer_dn: string
  rights: string
  is_domain_controller: boolean
}

export interface ConstrainedDelegationToDC {
  account_name: string
  distinguished_name: string
  delegation_target: string
  is_protocol_transition: boolean
}

export interface ESC1Vulnerability {
  template_name: string
  template_dn: string
  enrollee_supplies_subject: boolean
  dangerous_eku: boolean
  no_manager_approval: boolean
  enroller: string
}

export interface ESC2Vulnerability {
  template_name: string
  template_dn: string
  has_any_purpose_eku: boolean
  has_no_eku: boolean
  enroller: string
}

export interface ESC3Vulnerability {
  template_name: string
  template_dn: string
  is_enrollment_agent: boolean
  authorized_signatures_required: number
  enroller: string
}

export interface ESC4Vulnerability {
  template_name: string
  template_dn: string
  principal: string
  write_access_type: string
}

export interface ESC5Vulnerability {
  object_name: string
  object_dn: string
  object_type: string
  principal: string
  write_access_type: string
}

export interface ESC7Vulnerability {
  ca_name: string
  ca_dn: string
  principal: string
  has_manage_ca: boolean
  has_manage_certificates: boolean
}

export interface ESC8Vulnerability {
  ca_name: string
  web_enrollment_server: string
  ntlm_enabled: boolean
}

export interface GPOControl {
  principal: string
  gpo_name: string
  gpo_guid: string
  gpo_dn: string
  rights: string
  linked_to_privileged_scope: boolean
}

export interface SessionGroupMembership {
  principal: string
  group_name: string
  attack_path: string
}

export interface LegacyLogonScript {
  account_name: string
  distinguished_name: string
  script_path: string
}

export interface AzureADConnect {
  account_name: string
  distinguished_name: string
  is_enabled: boolean
  description?: string
}

export interface GhostAccount {
  sam_account_name: string
  distinguished_name: string
  admin_count: number
  in_protected_group: boolean
}

export interface ShadowCredential {
  object_name: string
  distinguished_name: string
  object_class: string
  has_key_credential_link: boolean
}

export interface SidHistoryEntry {
  sam_account_name: string
  distinguished_name: string
  injected_sid: string
  is_same_domain: boolean
  is_privileged_rid: boolean
  rid?: string
}

export interface DCSyncRight {
  principal: string
  rights: string[]
  has_full_dcsync: boolean
}

export interface PKIVulnerability {
  target_type: string
  target_name: string
  principal: string
  rights: string
  attack_vector: string
}

export interface LapsExposure {
  computer_name: string
  principal: string
  can_read_password: boolean
  can_write_expiration: boolean
}

export interface GmsaExposure {
  gmsa_name: string
  principal: string
  can_read_password: boolean
}

export interface DangerousGroupMember {
  group_name: string
  member_sam_account_name: string
  member_dn: string
  attack_path: string
}

export interface WeakPasswordConfig {
  account: string
  issue: string
  risk: string
}

export interface DAEquivalenceFinding {
  category: string
  issue: string
  severity: string
  severity_level: number
  affected_object: string
  description: string
  impact: string
  remediation: string
  evidence: EquivalenceEvidence[]
}

export interface DAEquivalenceRecommendation {
  priority: number
  title: string
  description: string
  steps: string[]
  reference?: string
}

export interface DAEquivalenceAudit {
  // Core Counters (11)
  total_equivalent_principals: number
  critical_principals: number
  ghost_accounts_count: number
  shadow_credentials_count: number
  sid_history_issues: number
  dcsync_principals: number
  pki_vulnerabilities: number
  laps_exposures: number
  gmsa_exposures: number
  dangerous_group_members: number
  weak_password_configs: number

  // Additional Counters (23)
  shadow_credential_write_count: number
  write_spn_count: number
  unconstrained_delegation_count: number
  rbcd_write_count: number
  dns_zone_control_count: number
  gpo_link_rights_count: number
  exchange_privexchange_count: number
  privileged_takeover_count: number
  group_membership_control_count: number
  ou_control_count: number
  computer_control_count: number
  gpo_control_count: number
  session_group_count: number
  legacy_logon_script_count: number
  constrained_delegation_to_dc_count: number
  esc1_count: number
  esc2_count: number
  esc3_count: number
  esc4_count: number
  esc5_count: number
  esc7_count: number
  esc8_count: number
  azure_ad_connect_count: number

  // Details Arrays - Core
  equivalent_principals: EquivalentPrincipal[]
  ghost_accounts: GhostAccount[]
  shadow_credentials: ShadowCredential[]
  sid_history_entries: SidHistoryEntry[]
  dcsync_rights: DCSyncRight[]
  pki_vulnerabilities_list: PKIVulnerability[]
  laps_exposures_list: LapsExposure[]
  gmsa_exposures_list: GmsaExposure[]
  dangerous_members: DangerousGroupMember[]
  weak_passwords: WeakPasswordConfig[]

  // Details Arrays - Additional
  shadow_credential_writes: ShadowCredentialWriteAccess[]
  write_spn_vulnerabilities: WriteSPNVulnerability[]
  unconstrained_delegations: UnconstrainedDelegation[]
  rbcd_write_accesses: RBCDWriteAccess[]
  dns_zone_controls: DNSZoneControl[]
  gpo_link_rights_list: GPOLinkRights[]
  exchange_privexchanges: ExchangePrivExchange[]
  privileged_takeovers: PrivilegedAccountTakeover[]
  group_membership_controls: GroupMembershipControl[]
  ou_controls: OUControl[]
  computer_controls: ComputerObjectControl[]
  gpo_controls: GPOControl[]
  session_group_memberships: SessionGroupMembership[]
  legacy_logon_scripts: LegacyLogonScript[]
  constrained_delegation_to_dcs: ConstrainedDelegationToDC[]
  esc1_vulnerabilities: ESC1Vulnerability[]
  esc2_vulnerabilities: ESC2Vulnerability[]
  esc3_vulnerabilities: ESC3Vulnerability[]
  esc4_vulnerabilities: ESC4Vulnerability[]
  esc5_vulnerabilities: ESC5Vulnerability[]
  esc7_vulnerabilities: ESC7Vulnerability[]
  esc8_vulnerabilities: ESC8Vulnerability[]
  azure_ad_connects: AzureADConnect[]

  // Findings and Metadata
  findings: DAEquivalenceFinding[]
  risk_score: number
  scan_timestamp: string
  recommendations: DAEquivalenceRecommendation[]
}

// ==========================================
// Mock Data for Group Audit
// ==========================================

const mockGroupAudit: GroupAudit = {
  total_groups_scanned: 12,
  groups_with_issues: 4,
  excessive_membership_count: 2,
  nested_groups_count: 3,
  disabled_users_count: 2,
  inactive_users_count: 1,
  critical_findings: 1,
  high_findings: 2,
  medium_findings: 3,
  low_findings: 0,
  groups: [
    {
      name: "Domain Admins",
      distinguished_name: "CN=Domain Admins,CN=Users,DC=company,DC=com",
      member_count: 8,
      threshold: 5,
      is_critical: true,
      nested_groups: [
        {
          sam_account_name: "IT-Admins",
          distinguished_name: "CN=IT-Admins,OU=Groups,DC=company,DC=com",
          object_class: "group",
          enabled: null,
          last_logon: null,
        },
      ],
      disabled_users: [
        {
          sam_account_name: "jsmith_old",
          distinguished_name: "CN=John Smith (Old),OU=Users,DC=company,DC=com",
          object_class: "user",
          enabled: false,
          last_logon: "2024-01-15T10:30:00Z",
        },
      ],
      inactive_users: [],
      all_members: [],
    },
    {
      name: "Backup Operators",
      distinguished_name: "CN=Backup Operators,CN=Builtin,DC=company,DC=com",
      member_count: 18,
      threshold: 15,
      is_critical: false,
      nested_groups: [],
      disabled_users: [],
      inactive_users: [
        {
          sam_account_name: "backup_svc_old",
          distinguished_name: "CN=Backup Service Old,OU=Service Accounts,DC=company,DC=com",
          object_class: "user",
          enabled: true,
          last_logon: "2024-06-01T08:00:00Z",
        },
      ],
      all_members: [],
    },
  ],
  findings: [
    {
      category: "Privileged Groups",
      issue: "Excessive Privileged Group Membership",
      severity: "Critical",
      severity_level: 4,
      affected_object: "Domain Admins",
      description: "The 'Domain Admins' group has 8 members, exceeding the recommended threshold of 5.",
      impact: "Over-privileged accounts increase the attack surface and make it harder to maintain accountability.",
      remediation:
        "Review and reduce membership. Remove unnecessary accounts and implement role-based access with custom delegated groups.\n\nPowerShell: Get-ADGroupMember -Identity 'Domain Admins' | Select-Object Name, SamAccountName",
      details: {
        group_dn: "CN=Domain Admins,CN=Users,DC=company,DC=com",
        member_count: 8,
        threshold: 5,
        members: ["administrator", "jsmith", "alee", "bwilson", "IT-Admins", "cjohnson", "dkim", "jsmith_old"],
      },
    },
    {
      category: "Privileged Groups",
      issue: "Nested Groups in Critical Privileged Group",
      severity: "High",
      severity_level: 3,
      affected_object: "Domain Admins",
      description:
        "The critical group 'Domain Admins' contains 1 nested group(s), which complicates access management.",
      impact:
        "Nested groups create choke points and can lead to unintentional privileged access. They make it difficult to audit who has access.",
      remediation:
        "Remove nested groups and add users directly, or create custom delegated groups instead.\n\nNested groups: IT-Admins\n\nPowerShell: Get-ADGroupMember -Identity 'Domain Admins' | Where-Object {$_.objectClass -eq 'group'}",
      details: {
        group_dn: "CN=Domain Admins,CN=Users,DC=company,DC=com",
        nested_groups: ["IT-Admins"],
      },
    },
    {
      category: "Privileged Groups",
      issue: "Disabled User in Privileged Group",
      severity: "Medium",
      severity_level: 2,
      affected_object: "Domain Admins - jsmith_old",
      description: "Disabled user 'jsmith_old' is still a member of privileged group 'Domain Admins'.",
      impact: "Disabled accounts in privileged groups should be removed to maintain clean access control.",
      remediation:
        "Remove the disabled user:\n\nPowerShell: Remove-ADGroupMember -Identity 'Domain Admins' -Members 'jsmith_old' -Confirm:$false",
      details: {
        group_dn: "CN=Domain Admins,CN=Users,DC=company,DC=com",
        user_dn: "CN=John Smith (Old),OU=Users,DC=company,DC=com",
      },
    },
  ],
  risk_score: 65,
  scan_timestamp: new Date().toISOString(),
  recommendations: [
    {
      priority: 1,
      title: "Reduce Privileged Group Membership",
      description: "Found 2 group(s) with excessive membership. Large privileged groups increase attack surface.",
      steps: [
        "Audit each privileged group: Get-ADGroupMember -Identity 'Domain Admins' | Select-Object Name, SamAccountName",
        "Identify accounts that don't require permanent privileged access",
        "Implement Just-In-Time (JIT) administration using PAM or similar solutions",
        "Create role-based groups with delegated permissions instead of Domain Admin",
        "Document legitimate members and their business justification",
      ],
    },
    {
      priority: 2,
      title: "Remove Nested Groups from Critical Groups",
      description: "Found 3 nested group(s) in critical privileged groups. Nested groups obscure true membership.",
      steps: [
        "List nested groups: Get-ADGroupMember -Identity 'Domain Admins' | Where-Object {$_.objectClass -eq 'group'}",
        "Enumerate actual users in nested groups recursively",
        "Remove nested groups and add users directly",
        "Consider creating delegated administration groups instead",
        "Document the change and update access control procedures",
      ],
    },
  ],
}

// ==========================================
// Mock Data for DA Equivalence Audit
// ==========================================

const mockDAEquivalenceAudit: DAEquivalenceAudit = {
  // Core Counters (11)
  total_equivalent_principals: 5,
  critical_principals: 3,
  ghost_accounts_count: 2,
  shadow_credentials_count: 1,
  sid_history_issues: 1,
  dcsync_principals: 1,
  pki_vulnerabilities: 2,
  laps_exposures: 3,
  gmsa_exposures: 1,
  dangerous_group_members: 4,
  weak_password_configs: 2,

  // Additional Counters (23)
  shadow_credential_write_count: 2,
  write_spn_count: 1,
  unconstrained_delegation_count: 3,
  rbcd_write_count: 2,
  dns_zone_control_count: 1,
  gpo_link_rights_count: 2,
  exchange_privexchange_count: 1,
  privileged_takeover_count: 3,
  group_membership_control_count: 2,
  ou_control_count: 1,
  computer_control_count: 4,
  gpo_control_count: 2,
  session_group_count: 1,
  legacy_logon_script_count: 2,
  constrained_delegation_to_dc_count: 1,
  esc1_count: 3,
  esc2_count: 1,
  esc3_count: 1,
  esc4_count: 2,
  esc5_count: 1,
  esc7_count: 1,
  esc8_count: 1,
  azure_ad_connect_count: 1,

  // Details Arrays - Core
  equivalent_principals: [],
  ghost_accounts: [
    {
      sam_account_name: "former_admin",
      distinguished_name: "CN=Former Admin,OU=Users,DC=company,DC=com",
      admin_count: 1,
      in_protected_group: false,
    },
    {
      sam_account_name: "test_da",
      distinguished_name: "CN=Test DA,OU=Test,DC=company,DC=com",
      admin_count: 1,
      in_protected_group: false,
    },
  ],
  shadow_credentials: [
    {
      object_name: "DC01$",
      distinguished_name: "CN=DC01,OU=Domain Controllers,DC=company,DC=com",
      object_class: "computer",
      has_key_credential_link: true,
    },
  ],
  sid_history_entries: [
    {
      sam_account_name: "migrated_admin",
      distinguished_name: "CN=Migrated Admin,OU=Users,DC=company,DC=com",
      injected_sid: "S-1-5-21-1234567890-1234567890-1234567890-512",
      is_same_domain: true,
      is_privileged_rid: true,
      rid: "512",
    },
  ],
  dcsync_rights: [
    {
      principal: "COMPANY\\ExchangeServers",
      rights: ["DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All"],
      has_full_dcsync: true,
    },
  ],
  pki_vulnerabilities_list: [
    {
      target_type: "Certificate Template",
      target_name: "WebServer",
      principal: "COMPANY\\Domain Users",
      rights: "Enroll",
      attack_vector: "ESC1 - Template allows SAN specification with domain user enrollment",
    },
    {
      target_type: "Certificate Authority",
      target_name: "COMPANY-CA",
      principal: "COMPANY\\Help Desk",
      rights: "ManageCA",
      attack_vector: "ESC7 - CA management rights allow certificate issuance manipulation",
    },
  ],
  laps_exposures_list: [
    {
      computer_name: "WORKSTATION01",
      principal: "COMPANY\\Help Desk",
      can_read_password: true,
      can_write_expiration: false,
    },
  ],
  gmsa_exposures_list: [
    {
      gmsa_name: "svc_sql$",
      principal: "COMPANY\\SQL-Admins",
      can_read_password: true,
    },
  ],
  dangerous_members: [
    {
      group_name: "Print Operators",
      member_sam_account_name: "print_admin",
      member_dn: "CN=Print Admin,OU=Users,DC=company,DC=com",
      attack_path: "Load printer drivers on DCs -> Execute code as SYSTEM",
    },
    {
      group_name: "Backup Operators",
      member_sam_account_name: "backup_user",
      member_dn: "CN=Backup User,OU=Users,DC=company,DC=com",
      attack_path: "Backup SAM/SYSTEM -> Extract credentials -> Full domain compromise",
    },
    {
      group_name: "DnsAdmins",
      member_sam_account_name: "dns_admin",
      member_dn: "CN=DNS Admin,OU=Users,DC=company,DC=com",
      attack_path: "Load arbitrary DLL in DNS service on DC -> Execute as SYSTEM",
    },
    {
      group_name: "Account Operators",
      member_sam_account_name: "acc_ops",
      member_dn: "CN=Account Ops,OU=Users,DC=company,DC=com",
      attack_path: "Modify non-protected accounts -> Add to privileged groups",
    },
  ],
  weak_passwords: [
    {
      account: "svc_legacy",
      issue: "Password Never Expires",
      risk: "Stale credentials remain valid indefinitely - extended attack window",
    },
    {
      account: "admin_test",
      issue: "Password Not Required",
      risk: "Account can have empty password - immediate takeover risk",
    },
  ],

  // Details Arrays - Additional
  shadow_credential_writes: [],
  write_spn_vulnerabilities: [],
  unconstrained_delegations: [],
  rbcd_write_accesses: [],
  dns_zone_controls: [],
  gpo_link_rights_list: [],
  exchange_privexchanges: [],
  privileged_takeovers: [],
  group_membership_controls: [],
  ou_controls: [],
  computer_controls: [],
  gpo_controls: [],
  session_group_memberships: [],
  legacy_logon_scripts: [],
  constrained_delegation_to_dcs: [],
  esc1_vulnerabilities: [],
  esc2_vulnerabilities: [],
  esc3_vulnerabilities: [],
  esc4_vulnerabilities: [],
  esc5_vulnerabilities: [],
  esc7_vulnerabilities: [],
  esc8_vulnerabilities: [],
  azure_ad_connects: [],
  findings: [
    {
      category: "Admin Equivalence",
      issue: "SID History Injection (Same Domain)",
      severity: "Critical",
      severity_level: 4,
      affected_object: "migrated_admin",
      description:
        "User 'migrated_admin' contains a SID from the CURRENT domain in its SID History (S-1-5-21-...-512). This is a definitive sign of a Golden Ticket or SID History injection attack.",
      impact:
        "SID History entries grant the user all permissions of the injected SID, potentially including Domain Admin rights.",
      remediation:
        "Clear the sIDHistory attribute immediately:\n\nPowerShell:\nSet-ADUser -Identity 'migrated_admin' -Clear sIDHistory\n\nReference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory",
      evidence: [
        {
          reason: "SID History contains: S-1-5-21-1234567890-1234567890-1234567890-512",
          target: "migrated_admin",
          attack_path: "SID History injection -> Instant privilege escalation",
          distinguished_name: "CN=Migrated Admin,OU=Users,DC=company,DC=com",
        },
      ],
    },
    {
      category: "Admin Equivalence",
      issue: "DCSync Replication Rights",
      severity: "Critical",
      severity_level: 4,
      affected_object: "COMPANY\\ExchangeServers",
      description:
        "Principal 'COMPANY\\ExchangeServers' has DCSync replication rights. This allows extraction of all password hashes from the domain.",
      impact: "DCSync allows complete domain compromise by extracting all user password hashes including krbtgt.",
      remediation:
        "Review if Exchange requires these rights. If using Exchange 2013+, consider removing:\n\nReference: https://adsecurity.org/?p=1729",
      evidence: [
        {
          reason: "Replication rights: DS-Replication-Get-Changes, DS-Replication-Get-Changes-All",
          target: "Domain Root",
          attack_path: "DCSync -> Extract all hashes -> Golden Ticket -> Full compromise",
          rights: "DS-Replication-Get-Changes, DS-Replication-Get-Changes-All",
        },
      ],
    },
    {
      category: "Admin Equivalence",
      issue: "AdminSDHolder Ghost Account",
      severity: "Medium",
      severity_level: 2,
      affected_object: "former_admin",
      description:
        "User 'former_admin' has 'adminCount=1' but is not a member of any protected group. This may indicate a leftover administrative account.",
      impact: "Ghost accounts retain protected ACLs even after removal from privileged groups.",
      remediation:
        "Clear adminCount and enable inheritance:\n\nPowerShell:\nSet-ADUser -Identity 'former_admin' -Clear adminCount",
      evidence: [
        {
          reason: "adminCount=1 without protected group membership",
          target: "CN=Former Admin,OU=Users,DC=company,DC=com",
          attack_path: "Frozen ACLs may hide unauthorized access",
        },
      ],
    },
    {
      category: "Admin Equivalence",
      issue: "Shadow Credentials Detected",
      severity: "High",
      severity_level: 3,
      affected_object: "DC01$",
      description:
        "Object 'DC01$' has 'msDS-KeyCredentialLink' populated. This indicates a potential Shadow Credentials attack.",
      impact: "Shadow Credentials allow attackers to authenticate as the target account without knowing the password.",
      remediation:
        "Investigate and clear if not WHfB:\n\nPowerShell:\nSet-ADObject -Identity 'CN=DC01,...' -Clear msDS-KeyCredentialLink",
      evidence: [
        {
          reason: "msDS-KeyCredentialLink attribute populated",
          target: "DC01$",
          attack_path: "Shadow Credentials -> Request TGT -> Full account takeover",
          additional_context: "Object class: computer",
        },
      ],
    },
    {
      category: "Admin Equivalence",
      issue: "Dangerous Built-in Group Membership: DnsAdmins",
      severity: "High",
      severity_level: 3,
      affected_object: "dns_admin",
      description:
        "User 'dns_admin' is a member of dangerous built-in group 'DnsAdmins', which provides privilege escalation paths.",
      impact: "Attack path: Load arbitrary DLL in DNS service on DC -> Execute as SYSTEM",
      remediation:
        "Remove user from DnsAdmins:\n\nPowerShell:\nRemove-ADGroupMember -Identity 'DnsAdmins' -Members 'dns_admin' -Confirm:$false",
      evidence: [
        {
          reason: "Member of DnsAdmins",
          target: "DnsAdmins",
          attack_path: "Load arbitrary DLL in DNS service on DC -> Execute as SYSTEM",
          distinguished_name: "CN=DNS Admin,OU=Users,DC=company,DC=com",
        },
      ],
    },
  ],
  risk_score: 85,
  scan_timestamp: new Date().toISOString(),
  recommendations: [
    {
      priority: 1,
      title: "Clear SID History Injection",
      description: "Found 1 SID History issue(s). Same-domain or privileged SIDs indicate potential attack.",
      steps: [
        "Find SID History: Get-ADUser -LDAPFilter '(sIDHistory=*)' -Properties sIDHistory",
        "Analyze each SID - same domain SIDs are ALWAYS malicious",
        "Clear immediately: Set-ADUser -Identity <user> -Clear sIDHistory",
        "Enable SID filtering on all trusts to prevent future attacks",
      ],
      reference: "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory",
    },
    {
      priority: 2,
      title: "Remove Unauthorized DCSync Rights",
      description: "Found 1 non-DC principal(s) with DCSync replication rights.",
      steps: [
        "List replication rights: (Get-Acl 'AD:\\DC=domain,DC=com').Access | Where-Object {$_.ObjectType -match '1131f6a'}",
        "Only Domain Controllers should have these rights",
        "Remove unauthorized ACEs from the domain root",
        "Monitor Event ID 4662 for replication attempts",
      ],
      reference: "https://adsecurity.org/?p=1729",
    },
    {
      priority: 3,
      title: "Investigate Shadow Credentials",
      description: "Found 1 object(s) with msDS-KeyCredentialLink populated.",
      steps: [
        "Find objects: Get-ADObject -LDAPFilter '(msDS-KeyCredentialLink=*)' -Properties msDS-KeyCredentialLink",
        "Verify if Windows Hello for Business is legitimately deployed",
        "If not WHfB, clear immediately: Set-ADObject -Identity <dn> -Clear msDS-KeyCredentialLink",
        "Monitor for re-creation using advanced threat detection",
      ],
      reference:
        "https://posts.specterops.io/shadow-credentials-abusing-key-credential-link-translation-to-en-9d8f9fb12be8",
    },
    {
      priority: 4,
      title: "Clear AdminSDHolder Ghost Accounts",
      description: "Found 2 ghost account(s) with adminCount=1 but no protected group membership.",
      steps: [
        "Find ghost accounts: Get-ADUser -LDAPFilter '(adminCount=1)' | check membership",
        "Clear adminCount: Set-ADUser -Identity <user> -Clear adminCount",
        "Enable inheritance: Use AD Users and Computers -> Security -> Advanced",
        "Verify permissions are correct after clearing",
      ],
      reference:
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups",
    },
    {
      priority: 5,
      title: "Review Dangerous Built-in Group Membership",
      description: "Found 4 member(s) in dangerous built-in groups.",
      steps: [
        "List members of dangerous groups",
        "Remove users unless absolutely required for job function",
        "Use delegated administration groups with limited scope instead",
        "Document any required membership with business justification",
      ],
      reference: "https://aka.ms/PrivilegedGroups",
    },
  ],
}

// ==========================================
// Missing Audit API Functions
// ==========================================

// DA Equivalence Audit
export async function auditDAEquivalence(): Promise<DAEquivalenceAudit> {
  return await invoke("audit_da_equivalence")
}

// Privileged Accounts Audit
export async function auditPrivilegedAccounts(): Promise<PrivilegedAccountSummary> {
  return await invoke("get_privileged_account_summary")
}

// KRBTGT Audit
export async function auditKrbtgt(): Promise<KrbtgtAgeAnalysis> {
  return await invoke("analyze_krbtgt")
}

// Domain Security Audit
export async function auditDomainSecurity(): Promise<DomainSecurityAudit> {
  return await invoke("audit_domain_security")
}

// Delegation Audit
export async function auditDelegation(): Promise<DelegationAudit> {
  return await invoke("audit_delegation")
}

// Permissions Audit
export async function auditPermissions(): Promise<PermissionsAudit> {
  return await invoke("audit_permissions")
}

// GPO Audit
export async function auditGPO(): Promise<GpoAudit> {
  return await invoke("audit_gpos")
}

// Domain Trusts Audit
export async function auditDomainTrusts(): Promise<DomainTrustAudit> {
  return await invoke("audit_domain_trusts")
}

// Privileged Groups Audit
export async function auditPrivilegedGroups(): Promise<GroupAudit> {
  return await invoke("audit_privileged_groups")
}

// ==========================================
// Performance Monitoring Types
// ==========================================

export interface PoolStats {
  connections_created: number
  connections_reused: number
  connections_failed: number
  current_active: number
  peak_active: number
  total_queries: number
  avg_query_time_ms: number
}

export interface CombinedCacheStats {
  results_size: number
  results_hits: number
  results_misses: number
  results_hit_rate: number
  realtime_size: number
  realtime_hits: number
  realtime_misses: number
  realtime_hit_rate: number
}

export interface ExecutionStats {
  total_operations: number
  successful: number
  failed: number
  total_duration_ms: number
  avg_operation_ms: number
  parallel_efficiency: number
  last_execution: string | null
}

export interface PerformanceStats {
  connection_pool: PoolStats | null
  cache: CombinedCacheStats
  executor: ExecutionStats
}

export interface ComprehensiveAuditResult {
  domain_security: DomainSecurityAudit | null
  gpo_audit: GpoAudit | null
  delegation_audit: DelegationAudit | null
  trust_audit: DomainTrustAudit | null
  permissions_audit: PermissionsAudit | null
  group_audit: GroupAudit | null
  da_equivalence_audit: DAEquivalenceAudit | null
  execution_stats: ExecutionStats
  errors: string[]
}

// ==========================================
// Performance Monitoring Mock Data
// ==========================================

const mockPoolStats: PoolStats = {
  connections_created: 5,
  connections_reused: 47,
  connections_failed: 0,
  current_active: 2,
  peak_active: 4,
  total_queries: 52,
  avg_query_time_ms: 45.3,
}

const mockCacheStats: CombinedCacheStats = {
  results_size: 8,
  results_hits: 156,
  results_misses: 23,
  results_hit_rate: 0.871,
  realtime_size: 3,
  realtime_hits: 89,
  realtime_misses: 45,
  realtime_hit_rate: 0.664,
}

const mockExecutorStats: ExecutionStats = {
  total_operations: 42,
  successful: 40,
  failed: 2,
  total_duration_ms: 12450,
  avg_operation_ms: 296.4,
  parallel_efficiency: 3.2,
  last_execution: new Date().toISOString(),
}

const mockPerformanceStats: PerformanceStats = {
  connection_pool: mockPoolStats,
  cache: mockCacheStats,
  executor: mockExecutorStats,
}

// ==========================================
// Performance Monitoring API Functions
// ==========================================

export async function getPerformanceStats(): Promise<PerformanceStats> {
  if (typeof window !== "undefined" && "__TAURI__" in window) {
    const { invoke } = await import("@tauri-apps/api/core")
    return invoke<PerformanceStats>("get_performance_stats")
  }
  // Return mock data for development
  return mockPerformanceStats
}

export async function invalidateCache(): Promise<void> {
  if (typeof window !== "undefined" && "__TAURI__" in window) {
    const { invoke } = await import("@tauri-apps/api/core")
    return invoke("invalidate_cache")
  }
  // Mock for development
  console.log("Cache invalidated (mock)")
}

export async function runComprehensiveAudit(): Promise<ComprehensiveAuditResult> {
  if (typeof window !== "undefined" && "__TAURI__" in window) {
    const { invoke } = await import("@tauri-apps/api/core")
    return invoke<ComprehensiveAuditResult>("run_comprehensive_audit")
  }
  // Return mock data for development
  await new Promise((resolve) => setTimeout(resolve, 3000)) // Simulate delay
  // Note: You'll need to define mockDomainSecurityAudit, mockGpoAudit, etc. if they aren't already defined.
  // For now, assuming they exist in the scope or are imported.
  return {
    domain_security: mockAdminSDHolderAnalysis, // Using a placeholder; replace with actual mock if available
    gpo_audit: mockGroupAudit, // Using a placeholder; replace with actual mock if available
    delegation_audit: mockDAEquivalenceAudit, // Using a placeholder; replace with actual mock if available
    trust_audit: mockDAEquivalenceAudit, // Using a placeholder; replace with actual mock if available
    permissions_audit: mockAdminSDHolderAnalysis, // Using a placeholder; replace with actual mock if available
    group_audit: mockGroupAudit,
    da_equivalence_audit: mockDAEquivalenceAudit,
    execution_stats: mockExecutorStats,
    errors: [],
  }
}

// ==========================================
// Multi-Domain Management API Functions
// ==========================================

export interface DomainInfo {
  id: number
  name: string
  server: string
  base_dn: string
  is_active: boolean
  status: { Connected: null } | { Disconnected: null } | { Error: string }
  last_connected: string | null
}

export async function addDomain(
  name: string,
  server: string,
  username: string,
  password: string,
  baseDn: string
): Promise<number> {
  if (typeof window !== "undefined" && "__TAURI__" in window) {
    const { invoke } = await import("@tauri-apps/api/core")
    return invoke<number>("add_domain", { name, server, username, password, baseDn })
  }
  // Mock for development
  console.log("Domain added (mock)", { name, server, baseDn })
  return Math.floor(Math.random() * 1000)
}

export async function getAllDomains(): Promise<DomainInfo[]> {
  if (typeof window !== "undefined" && "__TAURI__" in window) {
    const { invoke } = await import("@tauri-apps/api/core")
    return invoke<DomainInfo[]>("get_all_domains")
  }
  // Mock for development
  return [
    {
      id: 1,
      name: "Production Domain",
      server: "dc.example.com:636",
      base_dn: "DC=example,DC=com",
      is_active: true,
      status: { Connected: null },
      last_connected: new Date().toISOString(),
    },
  ]
}

export async function switchDomain(domainId: number): Promise<void> {
  if (typeof window !== "undefined" && "__TAURI__" in window) {
    const { invoke } = await import("@tauri-apps/api/core")
    return invoke("switch_domain", { domainId })
  }
  // Mock for development
  console.log("Domain switched (mock)", domainId)
}

export async function deleteDomain(domainId: number): Promise<void> {
  if (typeof window !== "undefined" && "__TAURI__" in window) {
    const { invoke } = await import("@tauri-apps/api/core")
    return invoke("delete_domain", { domainId })
  }
  // Mock for development
  console.log("Domain deleted (mock)", domainId)
}

export async function testDomainConnection(
  server: string,
  username: string,
  password: string,
  baseDn: string
): Promise<boolean> {
  if (typeof window !== "undefined" && "__TAURI__" in window) {
    const { invoke } = await import("@tauri-apps/api/core")
    return invoke<boolean>("test_domain_connection", { server, username, password, baseDn })
  }
  // Mock for development
  console.log("Testing domain connection (mock)", { server, baseDn })
  await new Promise((resolve) => setTimeout(resolve, 1000))
  return true
}

export async function getActiveDomainInfo(): Promise<DomainInfo | null> {
  if (typeof window !== "undefined" && "__TAURI__" in window) {
    const { invoke } = await import("@tauri-apps/api/core")
    return invoke<DomainInfo | null>("get_active_domain_info")
  }
  // Mock for development
  return {
    id: 1,
    name: "Production Domain",
    server: "dc.example.com:636",
    base_dn: "DC=example,DC=com",
    is_active: true,
    status: { Connected: null },
    last_connected: new Date().toISOString(),
  }
}
