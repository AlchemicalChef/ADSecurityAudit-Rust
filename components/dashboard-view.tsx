/**
 * Dashboard View Component
 *
 * Main security dashboard providing an executive overview of Active Directory
 * security posture. Aggregates data from multiple audit sources to display:
 *
 * - Critical security findings count and severity breakdown
 * - Tier 0 privileged account statistics
 * - KRBTGT password age and rotation status
 * - ADCS (AD Certificate Services) vulnerability summary
 * - Risk scoring trends and recommendations
 *
 * @module components/dashboard-view
 *
 * Features:
 * - Real-time audit progress tracking with visual feedback
 * - Drill-down dialogs for detailed findings
 * - Interactive charts (bar and pie) for data visualization
 * - Auto-refresh capability for continuous monitoring
 *
 * Data Sources:
 * - DA Equivalence Audit (shadow admin detection)
 * - Privileged Accounts Summary
 * - KRBTGT Analysis
 * - AdminSDHolder Analysis
 * - GPO Security Audit
 */
"use client"

import { useEffect, useState, useCallback } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  auditDAEquivalence,
  auditPrivilegedAccounts,
  auditKrbtgt,
  analyzeAdminSDHolder,
  getPrivilegedGroups,
  auditGPO,
  listenToAuditProgress,
  type DAEquivalenceAudit,
  type PrivilegedAccountSummary,
  type KrbtgtAgeAnalysis,
  type AdminSDHolderAnalysis,
  type PrivilegedGroup,
  type GpoAudit,
  type AuditProgressEvent,
  type UnlistenFn,
} from "@/lib/tauri-api"
import {
  AlertTriangle,
  Shield,
  Users,
  Key,
  Clock,
  TrendingUp,
  RefreshCw,
  ShieldAlert,
  Database,
  ChevronRight,
  X,
  Info,
  CheckCircle,
  Loader2,
} from "lucide-react"
import { Progress } from "@/components/ui/progress"
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer } from "recharts"

type DetailDialogType = 'critical-findings' | 'tier0-accounts' | 'krbtgt-age' | 'esc-vulns' | null

interface DashboardData {
  daEquivalence: DAEquivalenceAudit | null
  privilegedAccounts: PrivilegedAccountSummary | null
  krbtgt: KrbtgtAgeAnalysis | null
  adminSDHolder: AdminSDHolderAnalysis | null
  privilegedGroups: PrivilegedGroup[] | null
  gpo: GpoAudit | null
}

interface LoadingProgress {
  daEquivalence: 'pending' | 'loading' | 'completed' | 'error'
  privilegedAccounts: 'pending' | 'loading' | 'completed' | 'error'
  krbtgt: 'pending' | 'loading' | 'completed' | 'error'
  adminSDHolder: 'pending' | 'loading' | 'completed' | 'error'
  privilegedGroups: 'pending' | 'loading' | 'completed' | 'error'
  gpo: 'pending' | 'loading' | 'completed' | 'error'
  // Granular progress from Tauri events
  currentMessage?: string
  currentAudit?: string
  checkProgress?: { current: number; total: number }
  itemsFound?: number
  // Error messages for each audit
  errorMessages?: { [key: string]: string }
}

interface DashboardViewProps {
  isConnected: boolean
}

export function DashboardView({ isConnected }: DashboardViewProps) {
  const [data, setData] = useState<DashboardData>({
    daEquivalence: null,
    privilegedAccounts: null,
    krbtgt: null,
    adminSDHolder: null,
    privilegedGroups: null,
    gpo: null,
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedDetail, setSelectedDetail] = useState<DetailDialogType>(null)
  const [loadingProgress, setLoadingProgress] = useState<LoadingProgress>({
    daEquivalence: 'pending',
    privilegedAccounts: 'pending',
    krbtgt: 'pending',
    adminSDHolder: 'pending',
    privilegedGroups: 'pending',
    gpo: 'pending',
  })

  const loadDashboardData = useCallback(async () => {
    if (!isConnected) {
      setLoading(false)
      return
    }

    setLoading(true)
    setError(null)
    setLoadingProgress({
      daEquivalence: 'pending',
      privilegedAccounts: 'pending',
      krbtgt: 'pending',
      adminSDHolder: 'pending',
      privilegedGroups: 'pending',
      gpo: 'pending',
      currentMessage: undefined,
      currentAudit: undefined,
      checkProgress: undefined,
      itemsFound: undefined,
    })

    // Set up progress event listener BEFORE starting audits
    let unlisten: UnlistenFn | null = null
    try {
      unlisten = await listenToAuditProgress((event: AuditProgressEvent) => {
        setLoadingProgress(prev => ({
          ...prev,
          currentMessage: event.message,
          currentAudit: event.audit_type,
          checkProgress: { current: event.current, total: event.total },
          itemsFound: event.items_found,
        }))
      })
    } catch (e) {
      console.error("Failed to set up progress listener:", e)
    }

    // Load data sequentially with progress updates
    let daEquiv: DAEquivalenceAudit | null = null
    let privAccounts: PrivilegedAccountSummary | null = null
    let krbtgtData: KrbtgtAgeAnalysis | null = null
    let adminSDHolderData: AdminSDHolderAnalysis | null = null
    let privilegedGroupsData: PrivilegedGroup[] | null = null
    let gpoData: GpoAudit | null = null

    const errors: string[] = []

    // Load KRBTGT
    setLoadingProgress(prev => ({ ...prev, krbtgt: 'loading' }))
    try {
      krbtgtData = await auditKrbtgt()
      setLoadingProgress(prev => ({ ...prev, krbtgt: 'completed' }))
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e)
      console.error("KRBTGT audit failed:", errMsg)
      errors.push(`KRBTGT: ${errMsg}`)
      setLoadingProgress(prev => ({
        ...prev,
        krbtgt: 'error',
        errorMessages: { ...prev.errorMessages, krbtgt: errMsg }
      }))
    }

    // Load AdminSDHolder
    setLoadingProgress(prev => ({ ...prev, adminSDHolder: 'loading' }))
    try {
      adminSDHolderData = await analyzeAdminSDHolder()
      setLoadingProgress(prev => ({ ...prev, adminSDHolder: 'completed' }))
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e)
      console.error("AdminSDHolder audit failed:", errMsg)
      errors.push(`AdminSDHolder: ${errMsg}`)
      setLoadingProgress(prev => ({
        ...prev,
        adminSDHolder: 'error',
        errorMessages: { ...prev.errorMessages, adminSDHolder: errMsg }
      }))
    }

    // Load Privileged Groups
    setLoadingProgress(prev => ({ ...prev, privilegedGroups: 'loading' }))
    try {
      privilegedGroupsData = await getPrivilegedGroups()
      setLoadingProgress(prev => ({ ...prev, privilegedGroups: 'completed' }))
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e)
      console.error("Privileged Groups audit failed:", errMsg)
      errors.push(`Privileged Groups: ${errMsg}`)
      setLoadingProgress(prev => ({
        ...prev,
        privilegedGroups: 'error',
        errorMessages: { ...prev.errorMessages, privilegedGroups: errMsg }
      }))
    }

    // Load GPO Audit
    setLoadingProgress(prev => ({ ...prev, gpo: 'loading' }))
    try {
      gpoData = await auditGPO()
      setLoadingProgress(prev => ({ ...prev, gpo: 'completed' }))
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e)
      console.error("GPO audit failed:", errMsg)
      errors.push(`GPO: ${errMsg}`)
      setLoadingProgress(prev => ({
        ...prev,
        gpo: 'error',
        errorMessages: { ...prev.errorMessages, gpo: errMsg }
      }))
    }

    // Load Privileged Accounts
    setLoadingProgress(prev => ({ ...prev, privilegedAccounts: 'loading' }))
    try {
      privAccounts = await auditPrivilegedAccounts()
      setLoadingProgress(prev => ({ ...prev, privilegedAccounts: 'completed' }))
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e)
      console.error("Privileged Accounts audit failed:", errMsg)
      errors.push(`Privileged Accounts: ${errMsg}`)
      setLoadingProgress(prev => ({
        ...prev,
        privilegedAccounts: 'error',
        errorMessages: { ...prev.errorMessages, privilegedAccounts: errMsg }
      }))
    }

    // Load DA Equivalence (last - most comprehensive with 19 checks)
    setLoadingProgress(prev => ({ ...prev, daEquivalence: 'loading' }))
    try {
      daEquiv = await auditDAEquivalence()
      setLoadingProgress(prev => ({ ...prev, daEquivalence: 'completed' }))
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e)
      console.error("DA Equivalence audit failed:", errMsg)
      errors.push(`DA Equivalence: ${errMsg}`)
      setLoadingProgress(prev => ({
        ...prev,
        daEquivalence: 'error',
        errorMessages: { ...prev.errorMessages, daEquivalence: errMsg }
      }))
    }

    // Set error message if any audits failed
    if (errors.length > 0) {
      setError(`Audit errors: ${errors.join(' | ')}`)
    }

    // Clean up event listener
    if (unlisten) {
      unlisten()
    }

    setData({
      daEquivalence: daEquiv,
      privilegedAccounts: privAccounts,
      krbtgt: krbtgtData,
      adminSDHolder: adminSDHolderData,
      privilegedGroups: privilegedGroupsData,
      gpo: gpoData,
    })

    setLoading(false)
  }, [isConnected])

  useEffect(() => {
    loadDashboardData()
  }, [loadDashboardData])

  // Calculate total critical findings
  const totalCriticalFindings =
    (data.daEquivalence?.findings.filter((f) => f.severity === "Critical").length || 0) +
    (data.privilegedAccounts?.high_risk_accounts || 0)

  // Calculate ESC vulnerabilities total
  const escTotal =
    (data.daEquivalence?.esc1_count || 0) +
    (data.daEquivalence?.esc2_count || 0) +
    (data.daEquivalence?.esc3_count || 0) +
    (data.daEquivalence?.esc4_count || 0) +
    (data.daEquivalence?.esc5_count || 0) +
    (data.daEquivalence?.esc7_count || 0) +
    (data.daEquivalence?.esc8_count || 0)

  // Prepare chart data
  const severityData = [
    {
      name: "Critical",
      count: data.daEquivalence?.findings.filter((f) => f.severity === "Critical").length || 0,
      color: "#ef4444",
    },
    {
      name: "High",
      count: data.daEquivalence?.findings.filter((f) => f.severity === "High").length || 0,
      color: "#f97316",
    },
    {
      name: "Medium",
      count: data.daEquivalence?.findings.filter((f) => f.severity === "Medium").length || 0,
      color: "#eab308",
    },
    { name: "Low", count: data.daEquivalence?.findings.filter((f) => f.severity === "Low").length || 0, color: "#3b82f6" },
  ]

  const escData = [
    { name: "ESC1", count: data.daEquivalence?.esc1_count || 0 },
    { name: "ESC2", count: data.daEquivalence?.esc2_count || 0 },
    { name: "ESC3", count: data.daEquivalence?.esc3_count || 0 },
    { name: "ESC4", count: data.daEquivalence?.esc4_count || 0 },
    { name: "ESC5", count: data.daEquivalence?.esc5_count || 0 },
    { name: "ESC7", count: data.daEquivalence?.esc7_count || 0 },
    { name: "ESC8", count: data.daEquivalence?.esc8_count || 0 },
  ].filter((item) => item.count > 0)

  const tierData = [
    { name: "Tier 0", count: data.privilegedAccounts?.total_tier0_accounts || 0, color: "#ef4444" },
    { name: "Tier 1", count: data.privilegedAccounts?.total_tier1_accounts || 0, color: "#f97316" },
    { name: "Tier 2", count: data.privilegedAccounts?.total_tier2_accounts || 0, color: "#eab308" },
  ]

  const getKrbtgtStatus = () => {
    if (!data.krbtgt) return { text: "Unknown", color: "text-muted-foreground" }
    if (data.krbtgt.age_days > 365) return { text: "Critical", color: "text-red-400" }
    if (data.krbtgt.age_days > 180) return { text: "Overdue", color: "text-orange-400" }
    if (data.krbtgt.age_days > 150) return { text: "Warning", color: "text-yellow-400" }
    return { text: "Healthy", color: "text-green-400" }
  }

  const getRiskScoreColor = (score: number) => {
    if (score >= 75) return "text-red-400"
    if (score >= 50) return "text-orange-400"
    if (score >= 25) return "text-yellow-400"
    return "text-green-400"
  }

  if (!isConnected) {
    return (
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <ShieldAlert className="mb-4 h-12 w-12 text-muted-foreground" />
          <h3 className="mb-2 text-lg font-semibold text-foreground">Not Connected to Active Directory</h3>
          <p className="text-center text-sm text-muted-foreground">
            Connect to Active Directory using the Connection tab to view dashboard metrics.
          </p>
        </CardContent>
      </Card>
    )
  }

  if (loading) {
    // Only count the audit status fields, not the granular progress fields
    const auditStatuses = [loadingProgress.daEquivalence, loadingProgress.privilegedAccounts, loadingProgress.krbtgt, loadingProgress.adminSDHolder, loadingProgress.privilegedGroups, loadingProgress.gpo]
    const completedCount = auditStatuses.filter(s => s === 'completed').length
    const totalCount = auditStatuses.length
    const progressPercent = (completedCount / totalCount) * 100

    const getStatusIcon = (status: 'pending' | 'loading' | 'completed' | 'error') => {
      switch (status) {
        case 'completed':
          return <CheckCircle className="h-4 w-4 text-green-500" />
        case 'loading':
          return <Loader2 className="h-4 w-4 text-primary animate-spin" />
        case 'error':
          return <AlertTriangle className="h-4 w-4 text-destructive" />
        default:
          return <div className="h-4 w-4 rounded-full border-2 border-muted-foreground/30" />
      }
    }

    return (
      <Card className="border-border bg-card">
        <CardContent className="py-12">
          <div className="max-w-md mx-auto space-y-6">
            <div className="text-center">
              <Shield className="h-12 w-12 text-primary mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-foreground mb-2">Collecting Security Data</h3>
              <p className="text-sm text-muted-foreground">Querying Active Directory for security metrics...</p>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Progress</span>
                <span className="text-foreground font-medium">{completedCount} of {totalCount} completed</span>
              </div>
              <Progress value={progressPercent} className="h-2" />
            </div>

            <div className="space-y-3">
              <div className={`flex items-center gap-3 p-3 rounded-lg ${loadingProgress.krbtgt === 'error' ? 'bg-destructive/10 border border-destructive/30' : loadingProgress.currentAudit === 'krbtgt' ? 'bg-primary/10 border border-primary/20' : 'bg-muted/50'}`}>
                {getStatusIcon(loadingProgress.krbtgt)}
                <div className="flex-1">
                  <p className="text-sm font-medium text-foreground">KRBTGT Analysis</p>
                  {loadingProgress.krbtgt === 'error' && loadingProgress.errorMessages?.krbtgt ? (
                    <p className="text-xs text-destructive">{loadingProgress.errorMessages.krbtgt}</p>
                  ) : loadingProgress.currentAudit === 'krbtgt' && loadingProgress.currentMessage ? (
                    <p className="text-xs text-primary">{loadingProgress.currentMessage}</p>
                  ) : (
                    <p className="text-xs text-muted-foreground">Analyzing KRBTGT password age and rotation status</p>
                  )}
                </div>
              </div>

              <div className={`flex items-center gap-3 p-3 rounded-lg ${loadingProgress.adminSDHolder === 'error' ? 'bg-destructive/10 border border-destructive/30' : loadingProgress.currentAudit === 'adminsdholder' ? 'bg-primary/10 border border-primary/20' : 'bg-muted/50'}`}>
                {getStatusIcon(loadingProgress.adminSDHolder)}
                <div className="flex-1">
                  <p className="text-sm font-medium text-foreground">AdminSDHolder Analysis</p>
                  {loadingProgress.adminSDHolder === 'error' && loadingProgress.errorMessages?.adminSDHolder ? (
                    <p className="text-xs text-destructive">{loadingProgress.errorMessages.adminSDHolder}</p>
                  ) : loadingProgress.currentAudit === 'adminsdholder' && loadingProgress.currentMessage ? (
                    <p className="text-xs text-primary">{loadingProgress.currentMessage}</p>
                  ) : (
                    <p className="text-xs text-muted-foreground">Analyzing AdminSDHolder security descriptor</p>
                  )}
                </div>
              </div>

              <div className={`flex items-center gap-3 p-3 rounded-lg ${loadingProgress.privilegedGroups === 'error' ? 'bg-destructive/10 border border-destructive/30' : loadingProgress.currentAudit === 'privileged_groups' ? 'bg-primary/10 border border-primary/20' : 'bg-muted/50'}`}>
                {getStatusIcon(loadingProgress.privilegedGroups)}
                <div className="flex-1">
                  <p className="text-sm font-medium text-foreground">Privileged Groups</p>
                  {loadingProgress.privilegedGroups === 'error' && loadingProgress.errorMessages?.privilegedGroups ? (
                    <p className="text-xs text-destructive">{loadingProgress.errorMessages.privilegedGroups}</p>
                  ) : loadingProgress.currentAudit === 'privileged_groups' && loadingProgress.currentMessage ? (
                    <div className="space-y-1">
                      <p className="text-xs text-primary">{loadingProgress.currentMessage}</p>
                      {loadingProgress.checkProgress && (
                        <div className="flex items-center gap-2">
                          <Progress value={(loadingProgress.checkProgress.current / loadingProgress.checkProgress.total) * 100} className="h-1 flex-1" />
                          <span className="text-xs text-muted-foreground">
                            {loadingProgress.checkProgress.current}/{loadingProgress.checkProgress.total}
                          </span>
                        </div>
                      )}
                      {loadingProgress.itemsFound !== undefined && loadingProgress.itemsFound > 0 && (
                        <p className="text-xs text-muted-foreground">Found {loadingProgress.itemsFound} groups</p>
                      )}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">Enumerating privileged group memberships</p>
                  )}
                </div>
              </div>

              <div className={`flex items-center gap-3 p-3 rounded-lg ${loadingProgress.gpo === 'error' ? 'bg-destructive/10 border border-destructive/30' : loadingProgress.currentAudit === 'gpo' ? 'bg-primary/10 border border-primary/20' : 'bg-muted/50'}`}>
                {getStatusIcon(loadingProgress.gpo)}
                <div className="flex-1">
                  <p className="text-sm font-medium text-foreground">GPO Audit</p>
                  {loadingProgress.gpo === 'error' && loadingProgress.errorMessages?.gpo ? (
                    <p className="text-xs text-destructive">{loadingProgress.errorMessages.gpo}</p>
                  ) : loadingProgress.currentAudit === 'gpo' && loadingProgress.currentMessage ? (
                    <div className="space-y-1">
                      <p className="text-xs text-primary">{loadingProgress.currentMessage}</p>
                      {loadingProgress.checkProgress && (
                        <div className="flex items-center gap-2">
                          <Progress value={(loadingProgress.checkProgress.current / loadingProgress.checkProgress.total) * 100} className="h-1 flex-1" />
                          <span className="text-xs text-muted-foreground">
                            {loadingProgress.checkProgress.current}/{loadingProgress.checkProgress.total}
                          </span>
                        </div>
                      )}
                      {loadingProgress.itemsFound !== undefined && loadingProgress.itemsFound > 0 && (
                        <p className="text-xs text-muted-foreground">Found {loadingProgress.itemsFound} GPOs</p>
                      )}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">Auditing Group Policy Objects and SYSVOL</p>
                  )}
                </div>
              </div>

              <div className={`flex items-center gap-3 p-3 rounded-lg ${loadingProgress.privilegedAccounts === 'error' ? 'bg-destructive/10 border border-destructive/30' : loadingProgress.currentAudit === 'privileged_accounts' ? 'bg-primary/10 border border-primary/20' : 'bg-muted/50'}`}>
                {getStatusIcon(loadingProgress.privilegedAccounts)}
                <div className="flex-1">
                  <p className="text-sm font-medium text-foreground">Privileged Accounts</p>
                  {loadingProgress.privilegedAccounts === 'error' && loadingProgress.errorMessages?.privilegedAccounts ? (
                    <p className="text-xs text-destructive">{loadingProgress.errorMessages.privilegedAccounts}</p>
                  ) : loadingProgress.currentAudit === 'privileged_accounts' && loadingProgress.currentMessage ? (
                    <div className="space-y-1">
                      <p className="text-xs text-primary">{loadingProgress.currentMessage}</p>
                      {loadingProgress.checkProgress && (
                        <div className="flex items-center gap-2">
                          <Progress value={(loadingProgress.checkProgress.current / loadingProgress.checkProgress.total) * 100} className="h-1 flex-1" />
                          <span className="text-xs text-muted-foreground">
                            {loadingProgress.checkProgress.current}/{loadingProgress.checkProgress.total}
                          </span>
                        </div>
                      )}
                      {loadingProgress.itemsFound !== undefined && loadingProgress.itemsFound > 0 && (
                        <p className="text-xs text-muted-foreground">Found {loadingProgress.itemsFound} accounts</p>
                      )}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">Enumerating Tier 0/1/2 privileged accounts</p>
                  )}
                </div>
              </div>

              <div className={`flex items-center gap-3 p-3 rounded-lg ${loadingProgress.daEquivalence === 'error' ? 'bg-destructive/10 border border-destructive/30' : loadingProgress.currentAudit === 'da_equivalence' ? 'bg-primary/10 border border-primary/20' : 'bg-muted/50'}`}>
                {getStatusIcon(loadingProgress.daEquivalence)}
                <div className="flex-1">
                  <p className="text-sm font-medium text-foreground">DA Equivalence Audit</p>
                  {loadingProgress.daEquivalence === 'error' && loadingProgress.errorMessages?.daEquivalence ? (
                    <p className="text-xs text-destructive">{loadingProgress.errorMessages.daEquivalence}</p>
                  ) : loadingProgress.currentAudit === 'da_equivalence' && loadingProgress.currentMessage ? (
                    <div className="space-y-1">
                      <p className="text-xs text-primary">{loadingProgress.currentMessage}</p>
                      {loadingProgress.checkProgress && (
                        <div className="flex items-center gap-2">
                          <Progress value={(loadingProgress.checkProgress.current / loadingProgress.checkProgress.total) * 100} className="h-1 flex-1" />
                          <span className="text-xs text-muted-foreground">
                            {loadingProgress.checkProgress.current}/{loadingProgress.checkProgress.total}
                          </span>
                        </div>
                      )}
                      {loadingProgress.itemsFound !== undefined && loadingProgress.itemsFound > 0 && (
                        <p className="text-xs text-muted-foreground">Found {loadingProgress.itemsFound} items</p>
                      )}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">Checking domain admin equivalent permissions (19 checks)</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Security Dashboard</h2>
          <p className="text-sm text-muted-foreground">Active Directory security posture overview</p>
        </div>
        <Button onClick={loadDashboardData} variant="outline">
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {error && (
        <Card className="border-destructive bg-destructive/10">
          <CardContent className="flex items-center gap-2 py-4">
            <AlertTriangle className="h-4 w-4 text-destructive" />
            <p className="text-sm text-destructive">{error}</p>
          </CardContent>
        </Card>
      )}

      {/* Metrics Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card
          className="border-border bg-card cursor-pointer hover:bg-accent/50 transition-colors"
          onClick={() => setSelectedDetail('critical-findings')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Critical Findings</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-400">{totalCriticalFindings}</div>
            <p className="text-xs text-muted-foreground">Require immediate action · Click for details</p>
          </CardContent>
        </Card>

        <Card
          className="border-border bg-card cursor-pointer hover:bg-accent/50 transition-colors"
          onClick={() => setSelectedDetail('tier0-accounts')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Tier 0 Accounts</CardTitle>
            <Users className="h-4 w-4 text-orange-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-400">{data.privilegedAccounts?.total_tier0_accounts || 0}</div>
            <p className="text-xs text-muted-foreground">
              {(data.privilegedAccounts?.total_tier0_accounts || 0) > 5 ? "Above recommended (≤5)" : "Within limits"} · Click for details
            </p>
          </CardContent>
        </Card>

        <Card
          className="border-border bg-card cursor-pointer hover:bg-accent/50 transition-colors"
          onClick={() => setSelectedDetail('krbtgt-age')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">KRBTGT Age</CardTitle>
            <Key className="h-4 w-4 text-yellow-400" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${getKrbtgtStatus().color}`}>
              {data.krbtgt?.age_days || 0} days
            </div>
            <p className="text-xs text-muted-foreground">Status: {getKrbtgtStatus().text} · Click for details</p>
          </CardContent>
        </Card>

        <Card
          className="border-border bg-card cursor-pointer hover:bg-accent/50 transition-colors"
          onClick={() => setSelectedDetail('esc-vulns')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">ESC Vulnerabilities</CardTitle>
            <ShieldAlert className="h-4 w-4 text-red-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-400">{escTotal}</div>
            <p className="text-xs text-muted-foreground">PKI/ADCS attack paths · Click for details</p>
          </CardContent>
        </Card>
      </div>

      {/* Risk Score Overview */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle>Overall Security Posture</CardTitle>
          <CardDescription>Domain-wide risk assessment based on all audits</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">DA Equivalence Risk Score</p>
              <p className={`text-4xl font-bold ${getRiskScoreColor(data.daEquivalence?.risk_score || 0)}`}>
                {data.daEquivalence?.risk_score || 0}/100
              </p>
            </div>
            <Shield className={`h-24 w-24 ${getRiskScoreColor(data.daEquivalence?.risk_score || 0)}`} />
          </div>
        </CardContent>
      </Card>

      {/* Charts Row */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Findings by Severity */}
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-base">Findings by Severity</CardTitle>
            <CardDescription>Distribution of security findings</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={severityData}>
                <XAxis dataKey="name" stroke="#888888" fontSize={12} />
                <YAxis stroke="#888888" fontSize={12} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#1e1e1e", border: "1px solid #333" }}
                  labelStyle={{ color: "#fff" }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Privileged Account Tiers */}
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-base">Privileged Account Distribution</CardTitle>
            <CardDescription>Accounts by tier level</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={tierData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, count }) => `${name}: ${count}`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="count"
                >
                  {tierData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: "#1e1e1e", border: "1px solid #333" }} />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* ESC Vulnerabilities Chart */}
      {escData.length > 0 && (
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-base">PKI/ADCS Vulnerabilities (ESC)</CardTitle>
            <CardDescription>Active Directory Certificate Services attack paths</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={escData} layout="vertical">
                <XAxis type="number" stroke="#888888" fontSize={12} />
                <YAxis dataKey="name" type="category" stroke="#888888" fontSize={12} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#1e1e1e", border: "1px solid #333" }}
                  labelStyle={{ color: "#fff" }}
                />
                <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}

      {/* Alerts Panel */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle>Critical Alerts</CardTitle>
          <CardDescription>High-priority security issues requiring attention</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {data.krbtgt && data.krbtgt.age_days > 180 && (
              <div className="flex items-start gap-3 rounded-lg border border-red-500/30 bg-red-500/10 p-3">
                <AlertTriangle className="h-5 w-5 text-red-400" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-red-400">KRBTGT Password Overdue</p>
                  <p className="text-xs text-muted-foreground">
                    KRBTGT password is {data.krbtgt.age_days} days old (recommended: ≤180 days). Rotate immediately to
                    mitigate Golden Ticket attacks.
                  </p>
                </div>
                <ChevronRight className="h-4 w-4 text-muted-foreground" />
              </div>
            )}

            {escTotal > 0 && (
              <div className="flex items-start gap-3 rounded-lg border border-red-500/30 bg-red-500/10 p-3">
                <ShieldAlert className="h-5 w-5 text-red-400" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-red-400">PKI/ADCS Vulnerabilities Detected</p>
                  <p className="text-xs text-muted-foreground">
                    {escTotal} ESC vulnerabilities found. These can lead to privilege escalation and credential theft.
                  </p>
                </div>
                <ChevronRight className="h-4 w-4 text-muted-foreground" />
              </div>
            )}

            {(data.privilegedAccounts?.total_tier0_accounts || 0) > 5 && (
              <div className="flex items-start gap-3 rounded-lg border border-orange-500/30 bg-orange-500/10 p-3">
                <Users className="h-5 w-5 text-orange-400" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-orange-400">Excessive Tier 0 Accounts</p>
                  <p className="text-xs text-muted-foreground">
                    {data.privilegedAccounts.total_tier0_accounts} Tier 0 accounts detected (recommended: ≤5). Reduce
                    permanent admin access and implement JIT privileges.
                  </p>
                </div>
                <ChevronRight className="h-4 w-4 text-muted-foreground" />
              </div>
            )}

            {totalCriticalFindings === 0 && (data.krbtgt?.age_days || 0) <= 180 && escTotal === 0 && (
              <div className="flex items-center justify-center py-8 text-center">
                <div>
                  <Shield className="mx-auto mb-2 h-12 w-12 text-green-400" />
                  <p className="text-sm font-medium text-green-400">No Critical Alerts</p>
                  <p className="text-xs text-muted-foreground">Your domain security posture looks healthy</p>
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
          <CardDescription>Run security audits and assessments</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-2 md:grid-cols-2 lg:grid-cols-3">
            <Button variant="outline" className="justify-start" onClick={loadDashboardData}>
              <Database className="mr-2 h-4 w-4" />
              Audit DA Equivalence
            </Button>
            <Button variant="outline" className="justify-start" onClick={loadDashboardData}>
              <Users className="mr-2 h-4 w-4" />
              Check Privileged Accounts
            </Button>
            <Button variant="outline" className="justify-start" onClick={loadDashboardData}>
              <Key className="mr-2 h-4 w-4" />
              Analyze KRBTGT
            </Button>
            <Button variant="outline" className="justify-start" onClick={loadDashboardData}>
              <ShieldAlert className="mr-2 h-4 w-4" />
              Audit Domain Security
            </Button>
            <Button variant="outline" className="justify-start" onClick={loadDashboardData}>
              <Clock className="mr-2 h-4 w-4" />
              Check Delegation
            </Button>
            <Button variant="outline" className="justify-start" onClick={loadDashboardData}>
              <TrendingUp className="mr-2 h-4 w-4" />
              Scan Permissions
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Detail Dialog */}
      <Dialog open={selectedDetail !== null} onOpenChange={() => setSelectedDetail(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {selectedDetail === 'critical-findings' && (
                <>
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                  Critical Findings Details
                </>
              )}
              {selectedDetail === 'tier0-accounts' && (
                <>
                  <Users className="h-5 w-5 text-orange-400" />
                  Tier 0 Accounts Details
                </>
              )}
              {selectedDetail === 'krbtgt-age' && (
                <>
                  <Key className="h-5 w-5 text-yellow-400" />
                  KRBTGT Account Details
                </>
              )}
              {selectedDetail === 'esc-vulns' && (
                <>
                  <ShieldAlert className="h-5 w-5 text-red-400" />
                  ESC Vulnerabilities Details
                </>
              )}
            </DialogTitle>
            <DialogDescription>
              {selectedDetail === 'critical-findings' && 'Security findings that require immediate attention'}
              {selectedDetail === 'tier0-accounts' && 'Accounts with domain-wide administrative privileges'}
              {selectedDetail === 'krbtgt-age' && 'KRBTGT password age and rotation recommendations'}
              {selectedDetail === 'esc-vulns' && 'Active Directory Certificate Services attack paths'}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 mt-4">
            {/* Critical Findings Details */}
            {selectedDetail === 'critical-findings' && (
              <>
                <div className="flex items-center justify-between p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <div>
                    <p className="text-sm text-muted-foreground">Total Critical Findings</p>
                    <p className="text-3xl font-bold text-red-400">{totalCriticalFindings}</p>
                  </div>
                  <AlertTriangle className="h-12 w-12 text-red-400/30" />
                </div>

                <div className="space-y-2">
                  <h4 className="font-semibold text-foreground">Breakdown by Source</h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                      <span className="text-sm text-foreground">DA Equivalence Critical Findings</span>
                      <Badge variant="destructive">
                        {data.daEquivalence?.findings.filter((f) => f.severity === "Critical").length || 0}
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                      <span className="text-sm text-foreground">High Risk Privileged Accounts</span>
                      <Badge variant="destructive">
                        {data.privilegedAccounts?.high_risk_accounts || 0}
                      </Badge>
                    </div>
                  </div>
                </div>

                {data.daEquivalence?.findings.filter((f) => f.severity === "Critical").length > 0 && (
                  <div className="space-y-2">
                    <h4 className="font-semibold text-foreground">Critical DA Equivalence Findings</h4>
                    <div className="space-y-2 max-h-60 overflow-y-auto">
                      {data.daEquivalence.findings
                        .filter((f) => f.severity === "Critical")
                        .slice(0, 5)
                        .map((finding, idx) => (
                          <div key={idx} className="p-3 bg-red-500/5 border border-red-500/20 rounded-lg">
                            <div className="flex items-start gap-2">
                              <AlertTriangle className="h-4 w-4 text-red-400 mt-0.5" />
                              <div className="flex-1">
                                <p className="text-sm font-medium text-foreground">{finding.title}</p>
                                <p className="text-xs text-muted-foreground mt-1">{finding.description}</p>
                                <div className="flex items-center gap-2 mt-2">
                                  <Badge variant="outline" className="text-xs">
                                    {finding.category}
                                  </Badge>
                                  <span className="text-xs text-muted-foreground">
                                    {finding.affected_objects?.length || 0} affected
                                  </span>
                                </div>
                              </div>
                            </div>
                          </div>
                        ))}
                      {data.daEquivalence.findings.filter((f) => f.severity === "Critical").length > 5 && (
                        <p className="text-xs text-center text-muted-foreground py-2">
                          +{data.daEquivalence.findings.filter((f) => f.severity === "Critical").length - 5} more findings
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </>
            )}

            {/* Tier 0 Accounts Details */}
            {selectedDetail === 'tier0-accounts' && (
              <>
                <div className="flex items-center justify-between p-4 bg-orange-500/10 border border-orange-500/30 rounded-lg">
                  <div>
                    <p className="text-sm text-muted-foreground">Total Tier 0 Accounts</p>
                    <p className="text-3xl font-bold text-orange-400">
                      {data.privilegedAccounts?.total_tier0_accounts || 0}
                    </p>
                  </div>
                  <Users className="h-12 w-12 text-orange-400/30" />
                </div>

                <div className="space-y-2">
                  <h4 className="font-semibold text-foreground">Account Statistics</h4>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="p-3 bg-muted rounded-lg">
                      <p className="text-xs text-muted-foreground">Enabled</p>
                      <p className="text-lg font-bold text-foreground">
                        {data.privilegedAccounts?.enabled_accounts || 0}
                      </p>
                    </div>
                    <div className="p-3 bg-muted rounded-lg">
                      <p className="text-xs text-muted-foreground">Disabled</p>
                      <p className="text-lg font-bold text-foreground">
                        {data.privilegedAccounts?.disabled_accounts || 0}
                      </p>
                    </div>
                    <div className="p-3 bg-muted rounded-lg">
                      <p className="text-xs text-muted-foreground">Locked</p>
                      <p className="text-lg font-bold text-foreground">
                        {data.privilegedAccounts?.locked_accounts || 0}
                      </p>
                    </div>
                    <div className="p-3 bg-muted rounded-lg">
                      <p className="text-xs text-muted-foreground">Kerberoastable</p>
                      <p className="text-lg font-bold text-foreground">
                        {data.privilegedAccounts?.kerberoastable_accounts || 0}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                  <div className="flex items-start gap-2">
                    <Info className="h-4 w-4 text-blue-400 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-blue-400">Best Practice Recommendation</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Microsoft recommends limiting Tier 0 accounts to ≤5 accounts.
                        {(data.privilegedAccounts?.total_tier0_accounts || 0) > 5
                          ? ` You currently have ${data.privilegedAccounts?.total_tier0_accounts} accounts, which exceeds this recommendation.`
                          : ' You are within the recommended limit.'}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <h4 className="font-semibold text-foreground">Additional Metrics</h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                      <span className="text-sm text-foreground">Stale Passwords (&gt;90 days)</span>
                      <Badge variant="outline">
                        {data.privilegedAccounts?.accounts_with_stale_passwords || 0}
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                      <span className="text-sm text-foreground">Password Never Expires</span>
                      <Badge variant="outline">
                        {data.privilegedAccounts?.accounts_password_never_expires || 0}
                      </Badge>
                    </div>
                  </div>
                </div>
              </>
            )}

            {/* KRBTGT Age Details */}
            {selectedDetail === 'krbtgt-age' && data.krbtgt && (
              <>
                <div className={`flex items-center justify-between p-4 border rounded-lg ${
                  data.krbtgt.age_days > 365 ? 'bg-red-500/10 border-red-500/30' :
                  data.krbtgt.age_days > 180 ? 'bg-orange-500/10 border-orange-500/30' :
                  data.krbtgt.age_days > 150 ? 'bg-yellow-500/10 border-yellow-500/30' :
                  'bg-green-500/10 border-green-500/30'
                }`}>
                  <div>
                    <p className="text-sm text-muted-foreground">Password Age</p>
                    <p className={`text-3xl font-bold ${getKrbtgtStatus().color}`}>
                      {data.krbtgt.age_days} days
                    </p>
                  </div>
                  <Key className={`h-12 w-12 ${getKrbtgtStatus().color} opacity-30`} />
                </div>

                <div className="space-y-2">
                  <h4 className="font-semibold text-foreground">KRBTGT Information</h4>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="p-3 bg-muted rounded-lg">
                      <p className="text-xs text-muted-foreground">Domain</p>
                      <p className="text-sm font-medium text-foreground truncate">
                        {data.krbtgt.account_info.domain}
                      </p>
                    </div>
                    <div className="p-3 bg-muted rounded-lg">
                      <p className="text-xs text-muted-foreground">Key Version</p>
                      <p className="text-sm font-medium text-foreground">
                        {data.krbtgt.account_info.key_version_number}
                      </p>
                    </div>
                    <div className="p-3 bg-muted rounded-lg col-span-2">
                      <p className="text-xs text-muted-foreground">Last Changed</p>
                      <p className="text-sm font-medium text-foreground">
                        {new Date(data.krbtgt.account_info.last_password_change).toLocaleString()}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <h4 className="font-semibold text-foreground">Risk Assessment</h4>
                  <div className={`p-4 border rounded-lg ${
                    data.krbtgt.risk_level === 'Critical' ? 'bg-red-500/10 border-red-500/30' :
                    data.krbtgt.risk_level === 'High' ? 'bg-orange-500/10 border-orange-500/30' :
                    data.krbtgt.risk_level === 'Medium' ? 'bg-yellow-500/10 border-yellow-500/30' :
                    'bg-blue-500/10 border-blue-500/30'
                  }`}>
                    <div className="flex items-center gap-2 mb-2">
                      <Badge variant="outline">{data.krbtgt.risk_level} Risk</Badge>
                      <span className={`text-sm ${
                        data.krbtgt.is_overdue ? 'text-red-400' : 'text-green-400'
                      }`}>
                        {data.krbtgt.is_overdue ? 'Overdue for rotation' : 'Within rotation schedule'}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Recommended maximum age: {data.krbtgt.recommended_max_age_days} days
                    </p>
                  </div>
                </div>

                {data.krbtgt.recommendations.length > 0 && (
                  <div className="space-y-2">
                    <h4 className="font-semibold text-foreground">Recommendations</h4>
                    <div className="space-y-2">
                      {data.krbtgt.recommendations.slice(0, 3).map((rec, idx) => (
                        <div key={idx} className={`p-3 border rounded-lg ${
                          rec.priority === 'Critical' ? 'bg-red-500/5 border-red-500/20' :
                          rec.priority === 'High' ? 'bg-orange-500/5 border-orange-500/20' :
                          'bg-yellow-500/5 border-yellow-500/20'
                        }`}>
                          <div className="flex items-start gap-2">
                            {rec.action_required && <AlertTriangle className="h-4 w-4 text-orange-400 mt-0.5" />}
                            <div className="flex-1">
                              <p className="text-sm font-medium text-foreground">{rec.title}</p>
                              <p className="text-xs text-muted-foreground mt-1">{rec.description}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}

            {/* ESC Vulnerabilities Details */}
            {selectedDetail === 'esc-vulns' && (
              <>
                <div className="flex items-center justify-between p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <div>
                    <p className="text-sm text-muted-foreground">Total ESC Vulnerabilities</p>
                    <p className="text-3xl font-bold text-red-400">{escTotal}</p>
                  </div>
                  <ShieldAlert className="h-12 w-12 text-red-400/30" />
                </div>

                <div className="space-y-2">
                  <h4 className="font-semibold text-foreground">Vulnerability Breakdown</h4>
                  <div className="space-y-2">
                    {escData.map((esc) => (
                      <div key={esc.name} className="flex items-center justify-between p-3 bg-muted rounded-lg">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-foreground">{esc.name}</span>
                          <Badge variant="outline" className="text-xs">
                            {esc.name === 'ESC1' ? 'Template Misconfiguration' :
                             esc.name === 'ESC2' ? 'Any Purpose EKU' :
                             esc.name === 'ESC3' ? 'Certificate Request Agent' :
                             esc.name === 'ESC4' ? 'Vulnerable Access Control' :
                             esc.name === 'ESC5' ? 'Vulnerable PKI Object' :
                             esc.name === 'ESC7' ? 'Vulnerable CA ACL' :
                             'ESC8 NTLM Relay'}
                          </Badge>
                        </div>
                        <Badge variant="destructive">{esc.count}</Badge>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-400 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-red-400">High Risk Alert</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        ESC vulnerabilities in Active Directory Certificate Services (ADCS) can allow privilege escalation
                        to Domain Admin. These should be remediated immediately as they represent critical attack paths.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                  <div className="flex items-start gap-2">
                    <Info className="h-4 w-4 text-blue-400 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-blue-400">Remediation Priority</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Focus on ESC1, ESC2, and ESC3 first as these are the most commonly exploited. Navigate to the
                        "DA Equiv" tab for detailed remediation steps for each vulnerability.
                      </p>
                    </div>
                  </div>
                </div>
              </>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
