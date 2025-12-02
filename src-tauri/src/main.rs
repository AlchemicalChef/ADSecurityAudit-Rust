// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ad_client;
mod incident;
mod security_analysis;
mod krbtgt;
mod privileged_accounts;
mod domain_security;
mod gpo_audit;
mod delegation_audit;
mod domain_trust_audit;
mod permissions_audit;
mod group_audit;
mod da_equivalence;
mod connection_pool;
mod query_cache;
mod parallel_executor;
mod ldap_utils;
mod ldap_timeout;
mod secure_types;
mod errors;
mod database;
mod forest_manager;
mod advanced_cache;
mod audit_log;
mod risk_scoring;
mod anomaly_detection;
mod domain_discovery;
mod infrastructure_audit;
mod common_types;
mod ldap_helpers;

use std::sync::Arc;
use tokio::sync::RwLock;
use tauri::{State, Emitter};

use ad_client::{ActiveDirectoryClient, UserInfo, ValidationResult};
use incident::{Incident, IncidentPriority, IncidentStatus};
use security_analysis::{AdminSDHolderAnalysis, AccessControlEntry};
use krbtgt::{KrbtgtAgeAnalysis, RotationRequest, RotationResult, RotationStatus};
use privileged_accounts::{PrivilegedAccount, PrivilegedAccountSummary, PrivilegedGroup};
use domain_security::DomainSecurityAudit;
use gpo_audit::GpoAudit;
use delegation_audit::DelegationAudit;
use domain_trust_audit::DomainTrustAudit;
use permissions_audit::PermissionsAudit;
use group_audit::GroupAudit;
use da_equivalence::DAEquivalenceAudit;
use infrastructure_audit::InfrastructureAudit;

use connection_pool::{LdapConnectionPool, PoolConfig, PoolStats};
use query_cache::{CacheManager, CacheKey};
use parallel_executor::{ParallelExecutor, ParallelConfig, ExecutionStats};
use database::Database;
use forest_manager::{ForestManager, DomainInfo};
use advanced_cache::AdvancedCache;
use audit_log::{AuditLogger, AuditEntry, AuditFilter, ComplianceStandard, AuditStatistics, ComplianceReport, Severity as AuditSeverity, Category as AuditCategory};
use risk_scoring::{RiskScoringEngine, UserRiskScore, DomainRiskScore};
use anomaly_detection::{AnomalyDetector, Anomaly, BehavioralBaseline, LogonEvent, EntityType};

use serde::{Serialize, Deserialize};
use tracing::{info, error, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveAuditResult {
    pub domain_security: Option<DomainSecurityAudit>,
    pub gpo_audit: Option<GpoAudit>,
    pub delegation_audit: Option<DelegationAudit>,
    pub trust_audit: Option<DomainTrustAudit>,
    pub permissions_audit: Option<PermissionsAudit>,
    pub group_audit: Option<GroupAudit>,
    pub da_equivalence_audit: Option<DAEquivalenceAudit>,
    pub infrastructure_audit: Option<InfrastructureAudit>,
    pub execution_stats: ExecutionStats,
    pub errors: Vec<String>,
}

/// Progress event emitted during audit operations
#[derive(Debug, Clone, Serialize)]
pub struct AuditProgressEvent {
    pub audit_type: String,
    pub phase: String,
    pub current: usize,
    pub total: usize,
    pub message: String,
    pub items_found: usize,
}

struct AppState {
    ad_client: RwLock<Option<ActiveDirectoryClient>>,  // Legacy - kept for backward compatibility
    connection_pool: RwLock<Option<Arc<LdapConnectionPool>>>,  // Legacy
    forest_manager: Arc<ForestManager>,  // New multi-domain manager
    cache: Arc<CacheManager>,
    executor: Arc<ParallelExecutor>,
    incidents: RwLock<Vec<Incident>>,
    krbtgt_rotation_status: RwLock<RotationStatus>,
    // Advanced features (Weeks 3-8)
    advanced_cache: Arc<AdvancedCache>,
    audit_logger: Arc<AuditLogger>,
    anomaly_detector: Arc<RwLock<AnomalyDetector>>,
}

#[tauri::command]
async fn get_performance_stats(
    state: State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let pool_stats: Option<PoolStats> = if let Some(pool) = state.connection_pool.read().await.as_ref() {
        Some(pool.stats().await)
    } else {
        None
    };

    let cache_stats = state.cache.combined_stats();
    let executor_stats = state.executor.stats().await;

    Ok(serde_json::json!({
        "connection_pool": pool_stats,
        "cache": cache_stats,
        "executor": executor_stats,
    }))
}

#[tauri::command]
async fn invalidate_cache(
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    state.cache.results.clear();
    state.cache.realtime.clear();
    Ok(())
}

#[tauri::command]
async fn run_comprehensive_audit(
    state: State<'_, Arc<AppState>>,
) -> Result<ComprehensiveAuditResult, String> {
    let ad_client = state.ad_client.read().await;
    let client = ad_client
        .as_ref()
        .ok_or_else(|| "Not connected to Active Directory".to_string())?;

    // Run all audits in parallel using tokio::join!
    let (
        domain_result,
        gpo_result,
        delegation_result,
        trust_result,
        permissions_result,
        group_result,
        da_result,
        infrastructure_result,
    ) = tokio::join!(
        client.audit_domain_security(),
        client.audit_gpos(),
        client.audit_delegation(),
        client.audit_domain_trusts(),
        client.audit_permissions(),
        client.audit_privileged_groups(),
        client.audit_da_equivalence(),
        client.audit_infrastructure_security(),
    );

    let mut errors = Vec::new();
    
    let domain_security = match domain_result {
        Ok(result) => Some(result),
        Err(e) => {
            errors.push(format!("Domain security audit failed: {}", e));
            None
        }
    };
    
    let gpo_audit = match gpo_result {
        Ok(result) => Some(result),
        Err(e) => {
            errors.push(format!("GPO audit failed: {}", e));
            None
        }
    };
    
    let delegation_audit = match delegation_result {
        Ok(result) => Some(result),
        Err(e) => {
            errors.push(format!("Delegation audit failed: {}", e));
            None
        }
    };
    
    let trust_audit = match trust_result {
        Ok(result) => Some(result),
        Err(e) => {
            errors.push(format!("Trust audit failed: {}", e));
            None
        }
    };
    
    let permissions_audit = match permissions_result {
        Ok(result) => Some(result),
        Err(e) => {
            errors.push(format!("Permissions audit failed: {}", e));
            None
        }
    };
    
    let group_audit = match group_result {
        Ok(result) => Some(result),
        Err(e) => {
            errors.push(format!("Group audit failed: {}", e));
            None
        }
    };
    
    let da_equivalence_audit = match da_result {
        Ok(result) => Some(result),
        Err(e) => {
            errors.push(format!("DA equivalence audit failed: {}", e));
            None
        }
    };

    let infrastructure_audit = match infrastructure_result {
        Ok(result) => Some(result),
        Err(e) => {
            errors.push(format!("Infrastructure audit failed: {}", e));
            None
        }
    };

    Ok(ComprehensiveAuditResult {
        domain_security,
        gpo_audit,
        delegation_audit,
        trust_audit,
        permissions_audit,
        group_audit,
        da_equivalence_audit,
        infrastructure_audit,
        execution_stats: state.executor.stats().await,
        errors,
    })
}

#[tauri::command]
async fn validate_credentials(
    server: String,
    username: String,
    password: String,
) -> Result<ValidationResult, String> {
    Ok(ActiveDirectoryClient::validate_credentials(&server, &username, &password).await)
}

#[tauri::command]
async fn purge_all_data(
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    // Clear all caches
    state.cache.results.clear();
    state.cache.realtime.clear();

    // Clear forest manager connections
    state.forest_manager.clear_all_domains().await;

    // Clear legacy AD client
    *state.ad_client.write().await = None;
    *state.connection_pool.write().await = None;

    // Reset rotation status
    *state.krbtgt_rotation_status.write().await = RotationStatus::default();

    // Clear incidents
    state.incidents.write().await.clear();

    Ok("All data purged successfully. Please reconnect to Active Directory.".to_string())
}

#[tauri::command]
async fn connect_ad(
    server: String,
    username: String,
    password: String,
    base_dn: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    info!("=== CONNECTION ATTEMPT ===");
    info!("Server: {}", server);
    info!("Base DN: {}", base_dn);
    info!("Using LDAPS: {}", server.contains(":636") || server.contains("ldaps://"));

    // Legacy connection method - also creates domain in ForestManager
    let client = match ActiveDirectoryClient::new(server.clone(), username.clone(), password.clone(), base_dn.clone()).await {
        Ok(c) => {
            info!("Successfully created AD client connection");
            c
        }
        Err(e) => {
            error!("=== CONNECTION FAILED ===");
            error!("Server: {}", server);
            error!("Error: {}", e);
            return Err(format!("Failed to connect to AD: {}", e));
        }
    };

    let pool_config = PoolConfig {
        max_connections: 10,
        ..Default::default()
    };
    let pool = LdapConnectionPool::new(
        server.clone(),
        username.clone(),
        password.clone(),
        base_dn.clone(),
        Some(pool_config),
    );
    info!("Connection pool created");

    // Update legacy state
    *state.ad_client.write().await = Some(client);
    *state.connection_pool.write().await = Some(Arc::new(pool));

    // Also save to ForestManager as "Default" domain
    let domain_name = format!("Default-{}", server.split(':').next().unwrap_or(&server));
    match state.forest_manager.add_domain(
        domain_name.clone(),
        server.clone(),
        username,
        password,
        base_dn.clone(),
    ).await {
        Ok(domain_id) => {
            info!("Domain added to ForestManager: {} (ID: {})", domain_name, domain_id);
            // Connect to the newly added domain
            match state.forest_manager.connect_domain(domain_id).await {
                Ok(_) => info!("Active domain set successfully"),
                Err(e) => {
                    error!("Failed to set active domain: {}", e);
                    return Err(format!("Failed to set active domain: {}", e));
                }
            }
        }
        Err(e) => {
            warn!("Domain add returned error (may already exist): {}", e);
            // Domain might already exist, try to find and connect
            if let Ok(domains) = state.forest_manager.get_all_domains() {
                if let Some(domain) = domains.iter().find(|d| d.name == domain_name) {
                    if let Some(id) = domain.id {
                        state.forest_manager.connect_domain(id).await.ok();
                        info!("Connected to existing domain: {}", domain_name);
                    }
                }
            }
        }
    }

    state.cache.invalidate_audits();

    info!("=== CONNECTION SUCCESS ===");
    info!("Connected to: {} with base DN: {}", server, base_dn);
    Ok("Successfully connected to Active Directory".to_string())
}

#[tauri::command]
async fn search_users(
    search_query: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<UserInfo>, String> {
    let cache_key = CacheKey::UserSearch(search_query.clone());
    if let Some(cached) = state.cache.realtime.get(&cache_key) {
        if let Ok(users) = serde_json::from_str(&cached) {
            return Ok(users);
        }
    }

    let ad_client = state.ad_client.read().await;
    let client = ad_client
        .as_ref()
        .ok_or_else(|| "Not connected to Active Directory".to_string())?;

    let result = client
        .search_users(&search_query)
        .await
        .map_err(|e| format!("Failed to search users: {}", e))?;

    if let Ok(json) = serde_json::to_string(&result) {
        state.cache.realtime.insert(cache_key, json);
    }

    Ok(result)
}

#[tauri::command]
async fn disable_user(
    distinguished_name: String,
    reason: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    let ad_client = state.ad_client.read().await;
    let client = ad_client
        .as_ref()
        .ok_or_else(|| "Not connected to Active Directory".to_string())?;

    client
        .disable_user(&distinguished_name, &reason)
        .await
        .map_err(|e| format!("Failed to disable user: {}", e))?;

    state.cache.invalidate_audits();

    Ok(format!(
        "User {} successfully disabled. Reason: {}",
        distinguished_name, reason
    ))
}

#[tauri::command]
async fn get_user_details(
    distinguished_name: String,
    state: State<'_, Arc<AppState>>,
) -> Result<UserInfo, String> {
    let ad_client = state.ad_client.read().await;
    let client = ad_client
        .as_ref()
        .ok_or_else(|| "Not connected to Active Directory".to_string())?;

    client
        .get_user_details(&distinguished_name)
        .await
        .map_err(|e| format!("Failed to get user details: {}", e))
}

#[tauri::command]
async fn create_incident(
    title: String,
    description: String,
    priority: String,
    affected_systems: Vec<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<Incident, String> {
    let priority = match priority.as_str() {
        "critical" => IncidentPriority::Critical,
        "high" => IncidentPriority::High,
        "medium" => IncidentPriority::Medium,
        "low" => IncidentPriority::Low,
        _ => return Err("Invalid priority".to_string()),
    };

    let incident = Incident::new(title, description, priority, affected_systems);
    state.incidents.write().await.push(incident.clone());

    Ok(incident)
}

#[tauri::command]
async fn get_incidents(state: State<'_, Arc<AppState>>) -> Result<Vec<Incident>, String> {
    let incidents = state.incidents.read().await;
    Ok(incidents.clone())
}

#[tauri::command]
async fn update_incident_status(
    incident_id: String,
    status: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Incident, String> {
    let status = match status.as_str() {
        "open" => IncidentStatus::Open,
        "investigating" => IncidentStatus::Investigating,
        "contained" => IncidentStatus::Contained,
        "resolved" => IncidentStatus::Resolved,
        "closed" => IncidentStatus::Closed,
        _ => return Err("Invalid status".to_string()),
    };

    let mut incidents = state.incidents.write().await;
    let incident = incidents
        .iter_mut()
        .find(|i| i.id == incident_id)
        .ok_or_else(|| "Incident not found".to_string())?;

    incident.update_status(status);
    Ok(incident.clone())
}

#[tauri::command]
async fn add_incident_action(
    incident_id: String,
    action_type: String,
    description: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Incident, String> {
    let mut incidents = state.incidents.write().await;
    let incident = incidents
        .iter_mut()
        .find(|i| i.id == incident_id)
        .ok_or_else(|| "Incident not found".to_string())?;

    incident.add_action(action_type, description);
    Ok(incident.clone())
}

#[tauri::command]
async fn analyze_adminsdholder(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<AdminSDHolderAnalysis, String> {
    info!("=== AUDIT: AdminSDHolder Analysis ===");

    let cache_key = CacheKey::AdminSDHolder;
    if let Some(cached) = state.cache.results.get(&cache_key) {
        if let Ok(result) = serde_json::from_str(&cached) {
            info!("AdminSDHolder: Returning cached result");
            return Ok(result);
        }
    }

    // Emit start progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "adminsdholder".into(),
        phase: "start".into(),
        current: 0,
        total: 1,
        message: "Analyzing AdminSDHolder security descriptor...".into(),
        items_found: 0,
    });

    let ad_client = state.ad_client.read().await;
    let client = match ad_client.as_ref() {
        Some(c) => c,
        None => {
            error!("AdminSDHolder Audit FAILED: Not connected to Active Directory");
            return Err("Not connected to Active Directory".to_string());
        }
    };

    info!("AdminSDHolder: Calling analyze_adminsdholder...");
    let result = match client.analyze_adminsdholder().await {
        Ok(r) => {
            info!("AdminSDHolder Audit SUCCESS: Found {} DACL entries, {} risky", r.dacl_entries.len(), r.risky_aces);
            r
        }
        Err(e) => {
            error!("AdminSDHolder Audit FAILED: {}", e);
            return Err(format!("Failed to analyze AdminSDHolder: {}", e));
        }
    };

    info!("AdminSDHolder: Emitting complete progress event");
    // Emit complete progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "adminsdholder".into(),
        phase: "complete".into(),
        current: 1,
        total: 1,
        message: "AdminSDHolder analysis complete".into(),
        items_found: result.dacl_entries.len(),
    });

    info!("AdminSDHolder: Caching result");
    if let Ok(json) = serde_json::to_string(&result) {
        state.cache.results.insert(cache_key, json);
        info!("AdminSDHolder: Result cached successfully");
    } else {
        warn!("AdminSDHolder: Failed to serialize result for caching");
    }

    info!("AdminSDHolder: Returning result to frontend");
    Ok(result)
}

#[tauri::command]
async fn get_adminsdholder_risky_aces(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<AccessControlEntry>, String> {
    let ad_client = state.ad_client.read().await;
    let client = ad_client
        .as_ref()
        .ok_or_else(|| "Not connected to Active Directory".to_string())?;

    client
        .get_adminsdholder_risky_aces()
        .await
        .map_err(|e| format!("Failed to get risky ACEs: {}", e))
}

#[tauri::command]
async fn analyze_krbtgt(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<KrbtgtAgeAnalysis, String> {
    info!("=== AUDIT: KRBTGT Analysis ===");

    // Emit start progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "krbtgt".into(),
        phase: "start".into(),
        current: 1,
        total: 1,
        message: "Analyzing KRBTGT account...".into(),
        items_found: 0,
    });

    let ad_client = state.ad_client.read().await;
    let client = match ad_client.as_ref() {
        Some(c) => c,
        None => {
            error!("KRBTGT Audit FAILED: Not connected to Active Directory");
            return Err("Not connected to Active Directory".to_string());
        }
    };

    let result = match client.analyze_krbtgt().await {
        Ok(r) => {
            info!("KRBTGT Audit SUCCESS: Password age {} days, Risk level: {:?}", r.age_days, r.risk_level);
            r
        }
        Err(e) => {
            error!("KRBTGT Audit FAILED: {}", e);
            return Err(format!("Failed to analyze KRBTGT: {}", e));
        }
    };

    // Emit complete progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "krbtgt".into(),
        phase: "complete".into(),
        current: 1,
        total: 1,
        message: "KRBTGT analysis complete".into(),
        items_found: 1,
    });

    Ok(result)
}

#[tauri::command]
async fn rotate_krbtgt(
    rotation_number: u8,
    confirm_understanding: bool,
    reason: String,
    state: State<'_, Arc<AppState>>,
) -> Result<RotationResult, String> {
    let ad_client = state.ad_client.read().await;
    let client = ad_client
        .as_ref()
        .ok_or_else(|| "Not connected to Active Directory".to_string())?;

    let current_status = state.krbtgt_rotation_status.read().await.clone();

    let request = RotationRequest {
        rotation_number,
        confirm_understanding,
        reason,
    };

    let result = client
        .rotate_krbtgt(request, current_status)
        .await
        .map_err(|e| format!("Failed to rotate KRBTGT: {}", e))?;

    // Update rotation status
    let mut status = state.krbtgt_rotation_status.write().await;
    if rotation_number == 1 {
        status.first_rotation_complete = true;
        status.first_rotation_time = Some(result.timestamp.clone());
        status.rotation_in_progress = true;
    } else if rotation_number == 2 {
        status.second_rotation_complete = true;
        status.second_rotation_time = Some(result.timestamp.clone());
        status.rotation_in_progress = false;
    }

    Ok(result)
}

#[tauri::command]
async fn get_krbtgt_rotation_status(
    state: State<'_, Arc<AppState>>,
) -> Result<RotationStatus, String> {
    let status = state.krbtgt_rotation_status.read().await;
    Ok(status.clone())
}

#[tauri::command]
async fn reset_krbtgt_rotation_status(
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let mut status = state.krbtgt_rotation_status.write().await;
    *status = RotationStatus {
        rotation_in_progress: false,
        first_rotation_complete: false,
        second_rotation_complete: false,
        first_rotation_time: None,
        second_rotation_time: None,
        time_since_first_rotation: None,
        ready_for_second_rotation: false,
        minimum_wait_hours: 10,
        recommended_wait_hours: 24,
    };
    Ok(())
}

#[tauri::command]
async fn enumerate_privileged_accounts(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<PrivilegedAccount>, String> {
    let cache_key = CacheKey::PrivilegedAccounts;
    if let Some(cached) = state.cache.results.get(&cache_key) {
        if let Ok(result) = serde_json::from_str(&cached) {
            return Ok(result);
        }
    }

    let ad_client = state.ad_client.read().await;
    let client = ad_client
        .as_ref()
        .ok_or_else(|| "Not connected to Active Directory".to_string())?;

    let result = client
        .enumerate_privileged_accounts()
        .await
        .map_err(|e| format!("Failed to enumerate privileged accounts: {}", e))?;

    if let Ok(json) = serde_json::to_string(&result) {
        state.cache.results.insert(cache_key, json);
    }

    Ok(result)
}

#[tauri::command]
async fn get_privileged_account_summary(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<PrivilegedAccountSummary, String> {
    info!("=== AUDIT: Privileged Accounts Summary ===");

    // Emit start progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "privileged_accounts".into(),
        phase: "start".into(),
        current: 0,
        total: 14,
        message: "Scanning privileged groups...".into(),
        items_found: 0,
    });

    let ad_client = state.ad_client.read().await;
    let client = match ad_client.as_ref() {
        Some(c) => c,
        None => {
            error!("Privileged Accounts Audit FAILED: Not connected to Active Directory");
            return Err("Not connected to Active Directory".to_string());
        }
    };

    // Create progress callback that emits Tauri events
    let app_handle = app.clone();
    let progress_callback: ad_client::ProgressCallback = Box::new(move |current, total, message| {
        let _ = app_handle.emit("audit-progress", AuditProgressEvent {
            audit_type: "privileged_accounts".into(),
            phase: "check".into(),
            current,
            total,
            message: message.to_string(),
            items_found: 0,
        });
    });

    let result = match client.get_privileged_account_summary_with_progress(Some(progress_callback)).await {
        Ok(r) => {
            info!("Privileged Accounts Audit SUCCESS: Tier0={}, Tier1={}, Tier2={}",
                r.total_tier0_accounts, r.total_tier1_accounts, r.total_tier2_accounts);
            r
        }
        Err(e) => {
            error!("Privileged Accounts Audit FAILED: {}", e);
            return Err(format!("Failed to get privileged account summary: {}", e));
        }
    };

    // Emit complete progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "privileged_accounts".into(),
        phase: "complete".into(),
        current: 14,
        total: 14,
        message: "Privileged accounts scan complete".into(),
        items_found: result.total_tier0_accounts + result.total_tier1_accounts + result.total_tier2_accounts,
    });

    Ok(result)
}

#[tauri::command]
async fn get_privileged_groups(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<PrivilegedGroup>, String> {
    info!("=== AUDIT: Privileged Groups ===");

    // Emit start progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "privileged_groups".into(),
        phase: "start".into(),
        current: 0,
        total: 14,
        message: "Enumerating privileged groups...".into(),
        items_found: 0,
    });

    let ad_client = state.ad_client.read().await;
    let client = match ad_client.as_ref() {
        Some(c) => c,
        None => {
            error!("Privileged Groups Audit FAILED: Not connected to Active Directory");
            return Err("Not connected to Active Directory".to_string());
        }
    };

    // Create progress callback
    let app_handle = app.clone();
    let progress_callback: ad_client::ProgressCallback = Box::new(move |current, total, message| {
        let _ = app_handle.emit("audit-progress", AuditProgressEvent {
            audit_type: "privileged_groups".into(),
            phase: "check".into(),
            current,
            total,
            message: message.to_string(),
            items_found: 0,
        });
    });

    let result = match client.get_privileged_groups_with_progress(Some(&progress_callback)).await {
        Ok(r) => {
            info!("Privileged Groups Audit SUCCESS: Found {} groups", r.len());
            r
        }
        Err(e) => {
            error!("Privileged Groups Audit FAILED: {}", e);
            return Err(format!("Failed to get privileged groups: {}", e));
        }
    };

    // Emit complete progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "privileged_groups".into(),
        phase: "complete".into(),
        current: 14,
        total: 14,
        message: "Privileged groups enumeration complete".into(),
        items_found: result.len(),
    });

    Ok(result)
}

#[tauri::command]
async fn audit_domain_security(
    state: State<'_, Arc<AppState>>,
) -> Result<DomainSecurityAudit, String> {
    let cache_key = CacheKey::DomainSecurityAudit;
    if let Some(cached) = state.cache.results.get(&cache_key) {
        if let Ok(result) = serde_json::from_str(&cached) {
            return Ok(result);
        }
    }

    let ad_client = state.ad_client.read().await;
    let client = ad_client
        .as_ref()
        .ok_or_else(|| "Not connected to Active Directory".to_string())?;

    let result = client
        .audit_domain_security()
        .await
        .map_err(|e| format!("Failed to audit domain security: {}", e))?;

    if let Ok(json) = serde_json::to_string(&result) {
        state.cache.results.insert(cache_key, json);
    }

    Ok(result)
}

#[tauri::command]
async fn audit_gpos(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<GpoAudit, String> {
    info!("=== AUDIT: GPO Audit ===");

    let cache_key = CacheKey::GpoAudit;
    if let Some(cached) = state.cache.results.get(&cache_key) {
        if let Ok(result) = serde_json::from_str(&cached) {
            info!("GPO Audit: Returning cached result");
            return Ok(result);
        }
    }

    // Emit start progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "gpo".into(),
        phase: "start".into(),
        current: 0,
        total: 4,
        message: "Starting GPO audit...".into(),
        items_found: 0,
    });

    let ad_client = state.ad_client.read().await;
    let client = match ad_client.as_ref() {
        Some(c) => c,
        None => {
            error!("GPO Audit FAILED: Not connected to Active Directory");
            return Err("Not connected to Active Directory".to_string());
        }
    };

    // Create progress callback
    let app_handle = app.clone();
    let progress_callback: ad_client::ProgressCallback = Box::new(move |current, total, message| {
        let _ = app_handle.emit("audit-progress", AuditProgressEvent {
            audit_type: "gpo".into(),
            phase: "check".into(),
            current,
            total,
            message: message.to_string(),
            items_found: 0,
        });
    });

    let result = match client.audit_gpos_with_progress(Some(progress_callback)).await {
        Ok(r) => {
            info!("GPO Audit SUCCESS: Found {} GPOs", r.gpos.len());
            r
        }
        Err(e) => {
            error!("GPO Audit FAILED: {}", e);
            return Err(format!("Failed to audit GPOs: {}", e));
        }
    };

    // Emit complete progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "gpo".into(),
        phase: "complete".into(),
        current: 4,
        total: 4,
        message: "GPO audit complete".into(),
        items_found: result.gpos.len(),
    });

    if let Ok(json) = serde_json::to_string(&result) {
        state.cache.results.insert(cache_key, json);
    }

    Ok(result)
}

#[tauri::command]
async fn audit_delegation(
    state: State<'_, Arc<AppState>>,
) -> Result<DelegationAudit, String> {
    let cache_key = CacheKey::DelegationAudit;
    if let Some(cached) = state.cache.results.get(&cache_key) {
        if let Ok(result) = serde_json::from_str(&cached) {
            return Ok(result);
        }
    }

    let ad_client = state.ad_client.read().await;
    let client = ad_client
        .as_ref()
        .ok_or_else(|| "Not connected to Active Directory".to_string())?;

    let result = client
        .audit_delegation()
        .await
        .map_err(|e| format!("Failed to audit delegation: {}", e))?;

    if let Ok(json) = serde_json::to_string(&result) {
        state.cache.results.insert(cache_key, json);
    }

    Ok(result)
}

#[tauri::command]
async fn audit_domain_trusts(
    state: State<'_, Arc<AppState>>,
) -> Result<DomainTrustAudit, String> {
    let cache_key = CacheKey::TrustAudit;
    if let Some(cached) = state.cache.results.get(&cache_key) {
        if let Ok(result) = serde_json::from_str(&cached) {
            return Ok(result);
        }
    }

    let ad_client = state.ad_client.read().await;
    let client = ad_client
        .as_ref()
        .ok_or_else(|| "Not connected to Active Directory".to_string())?;

    let result = client
        .audit_domain_trusts()
        .await
        .map_err(|e| format!("Failed to audit domain trusts: {}", e))?;

    if let Ok(json) = serde_json::to_string(&result) {
        state.cache.results.insert(cache_key, json);
    }

    Ok(result)
}

#[tauri::command]
async fn audit_permissions(
    state: State<'_, Arc<AppState>>,
) -> Result<PermissionsAudit, String> {
    let cache_key = CacheKey::PermissionsAudit;
    if let Some(cached) = state.cache.results.get(&cache_key) {
        if let Ok(result) = serde_json::from_str(&cached) {
            return Ok(result);
        }
    }

    let ad_client = state.ad_client.read().await;
    let client = ad_client
        .as_ref()
        .ok_or_else(|| "Not connected to Active Directory".to_string())?;

    let result = client
        .audit_permissions()
        .await
        .map_err(|e| format!("Failed to audit permissions: {}", e))?;

    if let Ok(json) = serde_json::to_string(&result) {
        state.cache.results.insert(cache_key, json);
    }

    Ok(result)
}

#[tauri::command]
async fn audit_privileged_groups(
    state: State<'_, Arc<AppState>>,
) -> Result<GroupAudit, String> {
    let cache_key = CacheKey::GroupAudit;
    if let Some(cached) = state.cache.results.get(&cache_key) {
        if let Ok(result) = serde_json::from_str(&cached) {
            return Ok(result);
        }
    }

    let ad_client = state.ad_client.read().await;
    let client = ad_client
        .as_ref()
        .ok_or_else(|| "Not connected to Active Directory".to_string())?;

    let result = client
        .audit_privileged_groups()
        .await
        .map_err(|e| format!("Failed to audit privileged groups: {}", e))?;

    if let Ok(json) = serde_json::to_string(&result) {
        state.cache.results.insert(cache_key, json);
    }

    Ok(result)
}

#[tauri::command]
async fn audit_infrastructure_security(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<InfrastructureAudit, String> {
    info!("=== AUDIT: Infrastructure Security ===");

    // Emit start progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "infrastructure".into(),
        phase: "start".into(),
        current: 0,
        total: 6,
        message: "Starting infrastructure security audit...".into(),
        items_found: 0,
    });

    let ad_client = state.ad_client.read().await;
    let client = match ad_client.as_ref() {
        Some(c) => c,
        None => {
            error!("Infrastructure Audit FAILED: Not connected to Active Directory");
            return Err("Not connected to Active Directory".to_string());
        }
    };

    let result = match client.audit_infrastructure_security().await {
        Ok(r) => {
            info!("Infrastructure Audit SUCCESS: Found {} findings, Risk score: {}",
                r.findings.len(), r.overall_risk_score);
            r
        }
        Err(e) => {
            error!("Infrastructure Audit FAILED: {}", e);
            return Err(format!("Failed to audit infrastructure security: {}", e));
        }
    };

    // Emit complete progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "infrastructure".into(),
        phase: "complete".into(),
        current: 6,
        total: 6,
        message: "Infrastructure security audit complete".into(),
        items_found: result.findings.len(),
    });

    Ok(result)
}

#[tauri::command]
async fn audit_da_equivalence(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<DAEquivalenceAudit, String> {
    info!("=== AUDIT: DA Equivalence ===");

    let cache_key = CacheKey::DAEquivalenceAudit;
    if let Some(cached) = state.cache.results.get(&cache_key) {
        if let Ok(result) = serde_json::from_str(&cached) {
            info!("DA Equivalence Audit: Returning cached result");
            return Ok(result);
        }
    }

    // Emit start progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "da_equivalence".into(),
        phase: "start".into(),
        current: 0,
        total: 19,
        message: "Starting DA equivalence audit...".into(),
        items_found: 0,
    });

    let ad_client = state.ad_client.read().await;
    let client = match ad_client.as_ref() {
        Some(c) => c,
        None => {
            error!("DA Equivalence Audit FAILED: Not connected to Active Directory");
            return Err("Not connected to Active Directory".to_string());
        }
    };

    // Create progress callback that emits Tauri events
    let app_handle = app.clone();
    let progress_callback: ad_client::ProgressCallback = Box::new(move |current, total, message| {
        let _ = app_handle.emit("audit-progress", AuditProgressEvent {
            audit_type: "da_equivalence".into(),
            phase: "check".into(),
            current,
            total,
            message: message.to_string(),
            items_found: 0,
        });
    });

    let result = match client.audit_da_equivalence_with_progress(Some(progress_callback)).await {
        Ok(r) => {
            info!("DA Equivalence Audit SUCCESS: Found {} findings, Risk score: {}", r.findings.len(), r.risk_score);
            r
        }
        Err(e) => {
            error!("DA Equivalence Audit FAILED: {}", e);
            return Err(format!("Failed to audit DA equivalence: {}", e));
        }
    };

    // Emit complete progress
    let _ = app.emit("audit-progress", AuditProgressEvent {
        audit_type: "da_equivalence".into(),
        phase: "complete".into(),
        current: 19,
        total: 19,
        message: "DA equivalence audit complete".into(),
        items_found: result.findings.len(),
    });

    if let Ok(json) = serde_json::to_string(&result) {
        state.cache.results.insert(cache_key, json);
    }

    Ok(result)
}

// ==========================================
// Multi-Domain Management Commands
// ==========================================

#[tauri::command]
async fn add_domain(
    name: String,
    server: String,
    username: String,
    password: String,
    base_dn: String,
    state: State<'_, Arc<AppState>>,
) -> Result<i64, String> {
    state.forest_manager
        .add_domain(name, server, username, password, base_dn)
        .await
        .map_err(|e| format!("Failed to add domain: {}", e))
}

#[tauri::command]
async fn get_all_domains(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<DomainInfo>, String> {
    state.forest_manager
        .get_domains_info()
        .await
        .map_err(|e| format!("Failed to get domains: {}", e))
}

#[tauri::command]
async fn switch_domain(
    domain_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    state.forest_manager
        .connect_domain(domain_id)
        .await
        .map_err(|e| format!("Failed to switch domain: {}", e))?;

    // Get the domain config to create a legacy client
    let domain_config = state.forest_manager
        .get_domain_config(domain_id)
        .map_err(|e| format!("Failed to get domain config: {}", e))?
        .ok_or_else(|| "Domain config not found".to_string())?;

    // Create a new client for the legacy ad_client state
    let legacy_client = ActiveDirectoryClient::new(
        domain_config.server.clone(),
        domain_config.username.clone(),
        domain_config.password.clone(),
        domain_config.base_dn.clone(),
    ).await.map_err(|e| format!("Failed to create legacy client: {}", e))?;

    // Update legacy ad_client state
    *state.ad_client.write().await = Some(legacy_client);

    // Update legacy connection pool
    let pool = state.forest_manager
        .get_active_pool()
        .await
        .map_err(|e| format!("Failed to get active pool: {}", e))?;

    *state.connection_pool.write().await = Some(pool);

    // Invalidate cache when switching domains
    state.cache.invalidate_audits();

    Ok("Successfully switched domain".to_string())
}

#[tauri::command]
async fn delete_domain(
    domain_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    state.forest_manager
        .delete_domain(domain_id)
        .await
        .map_err(|e| format!("Failed to delete domain: {}", e))
}

#[tauri::command]
async fn test_domain_connection(
    server: String,
    username: String,
    password: String,
    base_dn: String,
    state: State<'_, Arc<AppState>>,
) -> Result<bool, String> {
    state.forest_manager
        .test_connection(server, username, password, base_dn)
        .await
        .map_err(|e| format!("Connection test failed: {}", e))
}

#[tauri::command]
async fn get_active_domain_info(
    state: State<'_, Arc<AppState>>,
) -> Result<Option<DomainInfo>, String> {
    let active_id = state.forest_manager.get_active_domain_id().await;

    if let Some(id) = active_id {
        let domains = state.forest_manager
            .get_domains_info()
            .await
            .map_err(|e| format!("Failed to get domain info: {}", e))?;

        Ok(domains.into_iter().find(|d| d.id == id))
    } else {
        Ok(None)
    }
}

// ==========================================
// Audit Logging Commands
// ==========================================

#[tauri::command]
async fn log_audit_event(
    category: String,
    severity: String,
    action: String,
    actor: String,
    target: Option<String>,
    result: String,
    domain_id: Option<i64>,
    domain_name: Option<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<i64, String> {
    let category_enum = match category.as_str() {
        "authentication" => AuditCategory::Authentication,
        "authorization" => AuditCategory::Authorization,
        "user_management" => AuditCategory::UserManagement,
        "group_management" => AuditCategory::GroupManagement,
        "privilege_escalation" => AuditCategory::PrivilegeEscalation,
        "configuration_change" => AuditCategory::ConfigurationChange,
        "data_access" => AuditCategory::DataAccess,
        "security_analysis" => AuditCategory::SecurityAnalysis,
        "incident_response" => AuditCategory::IncidentResponse,
        "compliance" => AuditCategory::Compliance,
        "system_event" => AuditCategory::SystemEvent,
        _ => return Err(format!("Invalid category: {}", category)),
    };

    let severity_enum = match severity.as_str() {
        "info" => AuditSeverity::Info,
        "warning" => AuditSeverity::Warning,
        "error" => AuditSeverity::Error,
        "critical" => AuditSeverity::Critical,
        _ => return Err(format!("Invalid severity: {}", severity)),
    };

    let entry = AuditEntry::new(
        domain_id,
        domain_name,
        category_enum,
        severity_enum,
        action,
        actor,
        target,
        result,
    );

    state.audit_logger
        .log(entry)
        .map_err(|e| format!("Failed to log audit event: {}", e))
}

#[tauri::command]
async fn query_audit_logs(
    start_time: Option<String>,
    end_time: Option<String>,
    category: Option<String>,
    severity: Option<String>,
    domain_id: Option<i64>,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<AuditEntry>, String> {
    use chrono::{DateTime, Utc};

    let start = start_time
        .map(|s| s.parse::<DateTime<Utc>>())
        .transpose()
        .map_err(|e| format!("Invalid start_time: {}", e))?;

    let end = end_time
        .map(|s| s.parse::<DateTime<Utc>>())
        .transpose()
        .map_err(|e| format!("Invalid end_time: {}", e))?;

    // Convert strings to enums if provided
    let category_enum = category.as_ref().and_then(|c| match c.as_str() {
        "authentication" => Some(AuditCategory::Authentication),
        "authorization" => Some(AuditCategory::Authorization),
        "user_management" => Some(AuditCategory::UserManagement),
        "group_management" => Some(AuditCategory::GroupManagement),
        "privilege_escalation" => Some(AuditCategory::PrivilegeEscalation),
        "configuration_change" => Some(AuditCategory::ConfigurationChange),
        "data_access" => Some(AuditCategory::DataAccess),
        "security_analysis" => Some(AuditCategory::SecurityAnalysis),
        "incident_response" => Some(AuditCategory::IncidentResponse),
        "compliance" => Some(AuditCategory::Compliance),
        "system_event" => Some(AuditCategory::SystemEvent),
        _ => None,
    });

    let severity_enum = severity.as_ref().and_then(|s| match s.as_str() {
        "info" => Some(AuditSeverity::Info),
        "warning" => Some(AuditSeverity::Warning),
        "error" => Some(AuditSeverity::Error),
        "critical" => Some(AuditSeverity::Critical),
        _ => None,
    });

    let filter = AuditFilter {
        start_time: start,
        end_time: end,
        domain_id,
        category: category_enum,
        severity: severity_enum,
        actor: None,
        limit: None,
    };

    state.audit_logger
        .query(filter)
        .map_err(|e| format!("Failed to query audit logs: {}", e))
}

#[tauri::command]
async fn get_audit_statistics(
    start_time: Option<String>,
    end_time: Option<String>,
    domain_id: Option<i64>,
    state: State<'_, Arc<AppState>>,
) -> Result<AuditStatistics, String> {
    use chrono::{DateTime, Utc};

    let start = start_time
        .map(|s| s.parse::<DateTime<Utc>>())
        .transpose()
        .map_err(|e| format!("Invalid start_time: {}", e))?;

    let end = end_time
        .map(|s| s.parse::<DateTime<Utc>>())
        .transpose()
        .map_err(|e| format!("Invalid end_time: {}", e))?;

    let filter = AuditFilter {
        start_time: start,
        end_time: end,
        domain_id,
        category: None,
        severity: None,
        actor: None,
        limit: None,
    };

    state.audit_logger
        .get_statistics(filter)
        .map_err(|e| format!("Failed to get audit statistics: {}", e))
}

#[tauri::command]
async fn generate_compliance_report(
    standard: String,
    start_time: String,
    end_time: String,
    state: State<'_, Arc<AppState>>,
) -> Result<ComplianceReport, String> {
    use chrono::{DateTime, Utc};

    let standard_enum = match standard.as_str() {
        "SOC2" => ComplianceStandard::SOC2,
        "HIPAA" => ComplianceStandard::HIPAA,
        "PCI_DSS" => ComplianceStandard::PCIDSS,
        "GDPR" => ComplianceStandard::GDPR,
        "ISO27001" => ComplianceStandard::ISO27001,
        _ => return Err(format!("Invalid standard: {}", standard)),
    };

    let start = start_time.parse::<DateTime<Utc>>()
        .map_err(|e| format!("Invalid start_time: {}", e))?;

    let end = end_time.parse::<DateTime<Utc>>()
        .map_err(|e| format!("Invalid end_time: {}", e))?;

    state.audit_logger
        .generate_compliance_report(standard_enum, start, end)
        .map_err(|e| format!("Failed to generate compliance report: {}", e))
}

// ==========================================
// Risk Scoring Commands
// ==========================================

#[tauri::command]
async fn score_user_risk(
    user_dn: String,
    username: String,
    is_privileged: bool,
    is_enabled: bool,
    last_logon: Option<String>,
    password_last_set: Option<String>,
    privileged_groups: Vec<String>,
    has_admin_rights: bool,
    failed_logon_count: u32,
    service_principal_names: Vec<String>,
) -> Result<UserRiskScore, String> {
    use chrono::{DateTime, Utc};

    let last_logon_dt = last_logon
        .map(|s| s.parse::<DateTime<Utc>>())
        .transpose()
        .map_err(|e| format!("Invalid last_logon: {}", e))?;

    let password_last_set_dt = password_last_set
        .map(|s| s.parse::<DateTime<Utc>>())
        .transpose()
        .map_err(|e| format!("Invalid password_last_set: {}", e))?;

    Ok(RiskScoringEngine::score_user(
        &user_dn,
        &username,
        is_privileged,
        is_enabled,
        last_logon_dt,
        password_last_set_dt,
        privileged_groups,
        has_admin_rights,
        failed_logon_count,
        service_principal_names,
    ))
}

#[tauri::command]
async fn score_domain_risk(
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
) -> Result<DomainRiskScore, String> {
    Ok(RiskScoringEngine::score_domain(
        domain_id,
        domain_name,
        krbtgt_age_days,
        admin_count,
        stale_admin_count,
        weak_password_count,
        gpo_issues_count,
        delegation_issues_count,
        trust_issues_count,
        permission_issues_count,
        previous_score,
    ))
}

// ==========================================
// Anomaly Detection Commands
// ==========================================

#[tauri::command]
async fn build_behavioral_baseline(
    entity: String,
    entity_type: String,
    logon_history: Vec<LogonEvent>,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let entity_type_enum = match entity_type.as_str() {
        "user" => EntityType::User,
        "computer" => EntityType::Computer,
        "group" => EntityType::Group,
        "service_account" => EntityType::ServiceAccount,
        _ => return Err(format!("Invalid entity_type: {}", entity_type)),
    };

    let mut detector = state.anomaly_detector.write().await;
    detector.build_baseline(entity, entity_type_enum, &logon_history);

    Ok(())
}

#[tauri::command]
async fn detect_logon_anomalies(
    entity: String,
    logon_event: LogonEvent,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<Anomaly>, String> {
    let detector = state.anomaly_detector.read().await;
    Ok(detector.detect_logon_anomalies(&entity, &logon_event))
}

#[tauri::command]
async fn detect_privilege_escalation(
    entity: String,
    old_groups: Vec<String>,
    new_groups: Vec<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<Anomaly>, String> {
    let detector = state.anomaly_detector.read().await;
    Ok(detector.detect_privilege_escalation(&entity, &old_groups, &new_groups))
}

#[tauri::command]
async fn detect_rapid_logons(
    entity: String,
    recent_logons: Vec<LogonEvent>,
    time_window_minutes: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<Option<Anomaly>, String> {
    let detector = state.anomaly_detector.read().await;
    Ok(detector.detect_rapid_logons(&entity, &recent_logons, time_window_minutes))
}

#[tauri::command]
async fn get_behavioral_baseline(
    entity: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Option<BehavioralBaseline>, String> {
    let detector = state.anomaly_detector.read().await;
    Ok(detector.get_baseline(&entity).cloned())
}

// ==========================================
// Advanced Cache Commands
// ==========================================

#[tauri::command]
async fn get_cache_statistics(
    state: State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let stats = state.advanced_cache.get_statistics().await;
    serde_json::to_value(stats)
        .map_err(|e| format!("Failed to serialize cache statistics: {}", e))
}

#[tauri::command]
async fn enable_cache_warming(
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    state.advanced_cache.enable_warming().await;
    Ok(())
}

#[tauri::command]
async fn disable_cache_warming(
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    state.advanced_cache.disable_warming().await;
    Ok(())
}

#[tauri::command]
async fn cleanup_expired_cache(
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    state.advanced_cache.cleanup_expired().await;
    Ok(())
}

#[tauri::command]
async fn invalidate_advanced_cache(
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    state.advanced_cache.invalidate_all();
    Ok(())
}

// ==========================================
// Domain Discovery Commands
// ==========================================

/// Discover domain information from the current Windows environment
#[tauri::command]
async fn discover_local_domain() -> Result<domain_discovery::DiscoveredDomainInfo, String> {
    info!("=== DOMAIN DISCOVERY REQUEST ===");

    // Run the blocking Windows API calls on a separate thread
    let result = tokio::task::spawn_blocking(|| {
        domain_discovery::discover_domain()
    })
    .await
    .map_err(|e| format!("Discovery task failed: {}", e))?;

    info!("Discovery complete: domain_joined={}, dc={:?}",
        result.is_domain_joined, result.domain_controller);

    Ok(result)
}

/// Quick check if the machine is domain-joined
#[tauri::command]
async fn is_domain_joined() -> Result<bool, String> {
    let result = tokio::task::spawn_blocking(|| {
        domain_discovery::check_domain_joined()
    })
    .await
    .map_err(|e| format!("Check failed: {}", e))?;

    Ok(result)
}

fn main() {
    // Set up file logging to AD.log
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, fmt, EnvFilter};
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use std::io;

    // Get log directory - use current exe directory or fallback to current dir
    let log_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    // Create a non-rolling file appender for AD.log
    let file_appender = RollingFileAppender::new(Rotation::NEVER, &log_dir, "AD.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Create file layer with detailed formatting
    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true);

    // Create console layer for stdout
    let console_layer = fmt::layer()
        .with_writer(io::stdout)
        .with_ansi(true);

    // Set up filter - log everything at INFO level and above
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // Initialize the subscriber with both layers
    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(console_layer)
        .init();

    // Log startup message with log file location
    tracing::info!("=======================================================");
    tracing::info!("ADSecurityScanner Starting");
    tracing::info!("Log file: {}", log_dir.join("AD.log").display());
    tracing::info!("=======================================================");

    // Keep the guard alive for the entire program
    // We'll leak it intentionally since the app runs until exit
    std::mem::forget(_guard);

    // Initialize database
    let database = Arc::new(Database::new(None).expect("Failed to initialize database"));

    // Initialize ForestManager
    let forest_manager = Arc::new(ForestManager::new(database));

    // Initialize advanced features
    let advanced_cache = Arc::new(AdvancedCache::new(
        100 * 1024 * 1024,  // 100MB cache size
        3600,  // 1 hour default TTL
    ));

    let audit_logger = Arc::new(
        AuditLogger::new(None)  // Uses default database path
            .expect("Failed to initialize audit logger")
    );

    let anomaly_detector = Arc::new(RwLock::new(
        AnomalyDetector::new(0.7)  // Balanced sensitivity
    ));

    let app_state = Arc::new(AppState {
        ad_client: RwLock::new(None),
        connection_pool: RwLock::new(None),
        forest_manager: forest_manager.clone(),
        cache: Arc::new(CacheManager::new()),
        executor: Arc::new(ParallelExecutor::new(ParallelConfig {
            max_concurrency: 5,
            ..Default::default()
        })),
        incidents: RwLock::new(Vec::new()),
        krbtgt_rotation_status: RwLock::new(RotationStatus {
            rotation_in_progress: false,
            first_rotation_complete: false,
            second_rotation_complete: false,
            first_rotation_time: None,
            second_rotation_time: None,
            time_since_first_rotation: None,
            ready_for_second_rotation: false,
            minimum_wait_hours: 10,
            recommended_wait_hours: 24,
        }),
        // Advanced features
        advanced_cache,
        audit_logger,
        anomaly_detector,
    });

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(move |_app| {
            // Initialize ForestManager asynchronously in the Tauri runtime
            let fm_clone = forest_manager.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = fm_clone.initialize().await {
                    eprintln!("Failed to initialize ForestManager: {}", e);
                }
            });
            Ok(())
        })
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            validate_credentials,
            purge_all_data,
            connect_ad,
            search_users,
            disable_user,
            get_user_details,
            create_incident,
            get_incidents,
            update_incident_status,
            add_incident_action,
            analyze_adminsdholder,
            get_adminsdholder_risky_aces,
            analyze_krbtgt,
            rotate_krbtgt,
            get_krbtgt_rotation_status,
            reset_krbtgt_rotation_status,
            enumerate_privileged_accounts,
            get_privileged_account_summary,
            get_privileged_groups,
            audit_domain_security,
            audit_gpos,
            audit_delegation,
            audit_domain_trusts,
            audit_permissions,
            audit_privileged_groups,
            audit_da_equivalence,
            audit_infrastructure_security,
            get_performance_stats,
            invalidate_cache,
            run_comprehensive_audit,
            // Multi-domain management commands
            add_domain,
            get_all_domains,
            switch_domain,
            delete_domain,
            test_domain_connection,
            get_active_domain_info,
            // Audit logging commands
            log_audit_event,
            query_audit_logs,
            get_audit_statistics,
            generate_compliance_report,
            // Risk scoring commands
            score_user_risk,
            score_domain_risk,
            // Anomaly detection commands
            build_behavioral_baseline,
            detect_logon_anomalies,
            detect_privilege_escalation,
            detect_rapid_logons,
            get_behavioral_baseline,
            // Advanced cache commands
            get_cache_statistics,
            enable_cache_warming,
            disable_cache_warming,
            cleanup_expired_cache,
            invalidate_advanced_cache,
            // Domain discovery commands
            discover_local_domain,
            is_domain_joined,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            eprintln!("Fatal error while running Tauri application: {}", e);
            std::process::exit(1);
        });
}
