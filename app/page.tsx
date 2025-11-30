"use client"

import { useState } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { DashboardView } from "@/components/dashboard-view"
import { UserManagement } from "@/components/user-management"
import { ADConnection } from "@/components/ad-connection"
import { AdminSDHolderAnalysisView } from "@/components/adminsdholder-analysis"
import { KrbtgtManagement } from "@/components/krbtgt-management"
import { PrivilegedAccounts } from "@/components/privileged-accounts"
import { DomainSecurityAuditView } from "@/components/domain-security-audit"
import { GpoAuditView } from "@/components/gpo-audit"
import { DelegationAuditView } from "@/components/delegation-audit"
import { DomainTrustAuditView } from "@/components/domain-trust-audit"
import { PermissionsAuditView } from "@/components/permissions-audit"
import { GroupAuditView } from "@/components/group-audit"
import { DAEquivalenceAuditView } from "@/components/da-equivalence-audit"
import { PerformanceMonitor } from "@/components/performance-monitor"
import { DomainSelector } from "@/components/domain-selector"
import { AuditLogViewer } from "@/components/audit-log-viewer"
import { RiskScoringDashboard } from "@/components/risk-scoring-dashboard"
import { AnomalyDetectionPanel } from "@/components/anomaly-detection-panel"
import { CacheStatisticsMonitor } from "@/components/cache-statistics-monitor"
import { SettingsDialog } from "@/components/settings-dialog"
import { ErrorBoundary } from "@/components/error-boundary"
import type { Credentials } from "@/components/credential-prompt"
import {
  Shield,
  AlertTriangle,
  Users,
  Settings,
  ShieldAlert,
  Key,
  UserCog,
  Server,
  FileText,
  Network,
  Lock,
  ArrowLeftRight,
  UsersRound,
  Skull,
  Activity,
  TrendingUp,
  Bell,
  Database,
} from "lucide-react"

export default function Page() {
  const [isConnected, setIsConnected] = useState(false)
  const [savedCredentials, setSavedCredentials] = useState<Credentials | undefined>()
  const [activeTab, setActiveTab] = useState("dashboard")

  const handleConnectionChange = (connected: boolean, credentials?: Credentials) => {
    setIsConnected(connected)
    if (connected && credentials) {
      setSavedCredentials({
        ...credentials,
        password: "",
      })
    } else if (!connected) {
      setSavedCredentials(undefined)
    }
  }

  const handleOpenConnectionDialog = () => {
    setActiveTab("connection")
  }

  return (
    <ErrorBoundary>
    <div className="flex h-screen flex-col bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="flex h-16 items-center justify-between px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary">
              <Shield className="h-6 w-6 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-foreground">ADSecurityScanner</h1>
              <p className="text-xs text-muted-foreground">Active Directory Security Scanner</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <DomainSelector onConnectionChange={(connected) => setIsConnected(connected)} />
            <div className="flex items-center gap-2">
              <div className={`h-2 w-2 rounded-full ${isConnected ? "bg-green-500" : "bg-destructive"}`} />
              <span className="text-sm text-muted-foreground">{isConnected ? "AD Connected" : "AD Disconnected"}</span>
            </div>
            <SettingsDialog onOpenConnectionDialog={handleOpenConnectionDialog} />
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 overflow-hidden">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="h-full">
          <div className="border-b border-border bg-card px-6 overflow-x-auto">
            <TabsList className="h-12 bg-transparent">
              <TabsTrigger value="dashboard" className="data-[state=active]:bg-accent">
                <Shield className="mr-2 h-4 w-4" />
                Dashboard
              </TabsTrigger>
              <TabsTrigger value="users" className="data-[state=active]:bg-accent">
                <Users className="mr-2 h-4 w-4" />
                Users
              </TabsTrigger>
              <TabsTrigger value="privileged" className="data-[state=active]:bg-accent">
                <UserCog className="mr-2 h-4 w-4" />
                Privileged
              </TabsTrigger>
              <TabsTrigger value="groups" className="data-[state=active]:bg-accent">
                <UsersRound className="mr-2 h-4 w-4" />
                Groups
              </TabsTrigger>
              <TabsTrigger value="da-equiv" className="data-[state=active]:bg-accent">
                <Skull className="mr-2 h-4 w-4" />
                DA Equiv
              </TabsTrigger>
              <TabsTrigger value="domain-security" className="data-[state=active]:bg-accent">
                <Server className="mr-2 h-4 w-4" />
                Domain
              </TabsTrigger>
              <TabsTrigger value="gpo-audit" className="data-[state=active]:bg-accent">
                <FileText className="mr-2 h-4 w-4" />
                GPO
              </TabsTrigger>
              <TabsTrigger value="delegation" className="data-[state=active]:bg-accent">
                <ArrowLeftRight className="mr-2 h-4 w-4" />
                Delegation
              </TabsTrigger>
              <TabsTrigger value="trusts" className="data-[state=active]:bg-accent">
                <Network className="mr-2 h-4 w-4" />
                Trusts
              </TabsTrigger>
              <TabsTrigger value="permissions" className="data-[state=active]:bg-accent">
                <Lock className="mr-2 h-4 w-4" />
                Permissions
              </TabsTrigger>
              <TabsTrigger value="adminsdholder" className="data-[state=active]:bg-accent">
                <ShieldAlert className="mr-2 h-4 w-4" />
                AdminSD
              </TabsTrigger>
              <TabsTrigger value="krbtgt" className="data-[state=active]:bg-accent">
                <Key className="mr-2 h-4 w-4" />
                KRBTGT
              </TabsTrigger>
              <TabsTrigger value="performance" className="data-[state=active]:bg-accent">
                <Activity className="mr-2 h-4 w-4" />
                Performance
              </TabsTrigger>
              <TabsTrigger value="audit-logs" className="data-[state=active]:bg-accent">
                <FileText className="mr-2 h-4 w-4" />
                Audit Logs
              </TabsTrigger>
              <TabsTrigger value="risk-scoring" className="data-[state=active]:bg-accent">
                <TrendingUp className="mr-2 h-4 w-4" />
                Risk Scoring
              </TabsTrigger>
              <TabsTrigger value="anomalies" className="data-[state=active]:bg-accent">
                <Bell className="mr-2 h-4 w-4" />
                Anomalies
              </TabsTrigger>
              <TabsTrigger value="cache" className="data-[state=active]:bg-accent">
                <Database className="mr-2 h-4 w-4" />
                Cache
              </TabsTrigger>
              <TabsTrigger value="connection" className="data-[state=active]:bg-accent">
                <Settings className="mr-2 h-4 w-4" />
                Connection
              </TabsTrigger>
            </TabsList>
          </div>

          <div className="h-[calc(100%-3rem)] overflow-auto relative">
            {/* Keep all tab contents mounted but only show active one */}
            <div className={`h-full p-6 ${activeTab === "dashboard" ? "block" : "hidden"}`}>
              <DashboardView isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "users" ? "block" : "hidden"}`}>
              <UserManagement isConnected={isConnected} savedCredentials={savedCredentials} />
            </div>
            <div className={`h-full p-6 ${activeTab === "privileged" ? "block" : "hidden"}`}>
              <PrivilegedAccounts isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "groups" ? "block" : "hidden"}`}>
              <GroupAuditView isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "da-equiv" ? "block" : "hidden"}`}>
              <DAEquivalenceAuditView isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "domain-security" ? "block" : "hidden"}`}>
              <DomainSecurityAuditView isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "gpo-audit" ? "block" : "hidden"}`}>
              <GpoAuditView isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "delegation" ? "block" : "hidden"}`}>
              <DelegationAuditView isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "trusts" ? "block" : "hidden"}`}>
              <DomainTrustAuditView isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "permissions" ? "block" : "hidden"}`}>
              <PermissionsAuditView isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "adminsdholder" ? "block" : "hidden"}`}>
              <AdminSDHolderAnalysisView isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "krbtgt" ? "block" : "hidden"}`}>
              <KrbtgtManagement isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "performance" ? "block" : "hidden"}`}>
              <PerformanceMonitor isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "audit-logs" ? "block" : "hidden"}`}>
              <AuditLogViewer isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "risk-scoring" ? "block" : "hidden"}`}>
              <RiskScoringDashboard isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "anomalies" ? "block" : "hidden"}`}>
              <AnomalyDetectionPanel isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "cache" ? "block" : "hidden"}`}>
              <CacheStatisticsMonitor isConnected={isConnected} />
            </div>
            <div className={`h-full p-6 ${activeTab === "connection" ? "block" : "hidden"}`}>
              <ADConnection isConnected={isConnected} onConnectionChange={handleConnectionChange} />
            </div>
          </div>
        </Tabs>
      </main>
    </div>
    </ErrorBoundary>
  )
}
