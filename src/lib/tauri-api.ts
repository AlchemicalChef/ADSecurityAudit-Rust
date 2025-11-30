import { invoke } from "@tauri-apps/api/core"

export interface UserInfo {
  distinguished_name: string
  username: string
  email: string
  display_name: string
  enabled: boolean
  last_logon?: string
  groups: string[]
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

export async function connectAD(server: string, username: string, password: string, baseDn: string): Promise<string> {
  return invoke("connect_ad", { server, username, password, baseDn })
}

export async function searchUsers(searchQuery: string): Promise<UserInfo[]> {
  return invoke("search_users", { searchQuery })
}

export async function disableUser(distinguishedName: string, reason: string): Promise<string> {
  return invoke("disable_user", { distinguishedName, reason })
}

export async function getUserDetails(distinguishedName: string): Promise<UserInfo> {
  return invoke("get_user_details", { distinguishedName })
}

export async function createIncident(
  title: string,
  description: string,
  priority: string,
  affectedSystems: string[],
): Promise<Incident> {
  return invoke("create_incident", {
    title,
    description,
    priority,
    affectedSystems,
  })
}

export async function getIncidents(): Promise<Incident[]> {
  return invoke("get_incidents")
}

export async function updateIncidentStatus(incidentId: string, status: string): Promise<Incident> {
  return invoke("update_incident_status", { incidentId, status })
}

export async function addIncidentAction(
  incidentId: string,
  actionType: string,
  description: string,
): Promise<Incident> {
  return invoke("add_incident_action", { incidentId, actionType, description })
}
