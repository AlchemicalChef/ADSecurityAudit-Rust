/**
 * AdminSDHolder Security Analysis Component
 *
 * Analyzes the security descriptor of the AdminSDHolder container and displays
 * Access Control Entries (ACEs) with risk assessment for each permission.
 *
 * @module components/adminsdholder-analysis
 *
 * AdminSDHolder Background:
 * The AdminSDHolder object in Active Directory serves as a template ACL for all
 * protected accounts. Every 60 minutes, the Security Descriptor Propagator (SDProp)
 * copies the AdminSDHolder's ACL to all protected accounts, overwriting any manual changes.
 *
 * Why This Matters:
 * - Misconfigurations here propagate to ALL protected accounts (Domain Admins, etc.)
 * - Attackers target AdminSDHolder for persistent privilege escalation
 * - Non-admin principals with write access can compromise the entire domain
 *
 * Risk Level Definitions:
 * - Critical: Full control, DCSync capability, or ownership rights
 * - High: Write permissions to sensitive attributes
 * - Medium: Ability to modify certain object properties
 * - Low: Extended read permissions beyond normal
 * - Info: Expected permissions for standard operations
 *
 * @see https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
 */
"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Progress } from "@/components/ui/progress"
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Info,
  CheckCircle,
  XCircle,
  Key,
  FileWarning,
  Loader2,
} from "lucide-react"
import {
  analyzeAdminSDHolder,
  type AdminSDHolderAnalysis,
  type AccessControlEntry,
  type RiskLevel,
  type SecurityRecommendation,
} from "@/lib/tauri-api"

interface AdminSDHolderAnalysisProps {
  isConnected: boolean
}

const riskLevelConfig: Record<RiskLevel, { color: string; bg: string; icon: typeof ShieldAlert }> = {
  Critical: { color: "text-red-400", bg: "bg-red-500/20 border-red-500/30", icon: ShieldAlert },
  High: { color: "text-orange-400", bg: "bg-orange-500/20 border-orange-500/30", icon: AlertTriangle },
  Medium: { color: "text-yellow-400", bg: "bg-yellow-500/20 border-yellow-500/30", icon: FileWarning },
  Low: { color: "text-blue-400", bg: "bg-blue-500/20 border-blue-500/30", icon: Info },
  Info: { color: "text-slate-400", bg: "bg-slate-500/20 border-slate-500/30", icon: CheckCircle },
}

function RiskBadge({ level }: { level: RiskLevel }) {
  const config = riskLevelConfig[level]
  return (
    <Badge variant="outline" className={`${config.bg} ${config.color} border`}>
      {level}
    </Badge>
  )
}

function AceCard({ ace, index }: { ace: AccessControlEntry; index: number }) {
  const [isOpen, setIsOpen] = useState(ace.risk_level === "Critical" || ace.risk_level === "High")
  const config = riskLevelConfig[ace.risk_level]
  const RiskIcon = config.icon

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <Card className={`border ${ace.risk_level !== "Info" ? config.bg : "bg-card"}`}>
        <CollapsibleTrigger className="w-full">
          <CardHeader className="py-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`flex h-8 w-8 items-center justify-center rounded-lg ${config.bg}`}>
                  <RiskIcon className={`h-4 w-4 ${config.color}`} />
                </div>
                <div className="text-left">
                  <CardTitle className="text-sm font-medium text-foreground">{ace.trustee}</CardTitle>
                  <CardDescription className="text-xs">{ace.trustee_sid}</CardDescription>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <RiskBadge level={ace.risk_level} />
                <Badge variant="outline" className="text-xs">
                  {ace.ace_type === "AccessAllowed" ? "Allow" : ace.ace_type === "AccessDenied" ? "Deny" : ace.ace_type}
                </Badge>
                {isOpen ? (
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                )}
              </div>
            </div>
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="border-t border-border pt-4">
            <div className="space-y-4">
              {/* Permissions */}
              <div>
                <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">Permissions</h4>
                <div className="flex flex-wrap gap-1.5">
                  {ace.permissions.map((perm, i) => (
                    <Badge key={i} variant="secondary" className="text-xs">
                      <Key className="mr-1 h-3 w-3" />
                      {perm}
                    </Badge>
                  ))}
                </div>
              </div>

              {/* Access Mask */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Access Mask:</span>
                  <code className="ml-2 rounded bg-muted px-1.5 py-0.5 text-xs">
                    0x{ace.access_mask.toString(16).toUpperCase().padStart(8, "0")}
                  </code>
                </div>
                <div>
                  <span className="text-muted-foreground">ACE Flags:</span>
                  <code className="ml-2 rounded bg-muted px-1.5 py-0.5 text-xs">
                    0x{ace.ace_flags.toString(16).toUpperCase().padStart(2, "0")}
                  </code>
                </div>
              </div>

              {/* Object Type */}
              {ace.object_type && (
                <div className="text-sm">
                  <span className="text-muted-foreground">Object Type GUID:</span>
                  <code className="ml-2 rounded bg-muted px-1.5 py-0.5 text-xs">{ace.object_type}</code>
                </div>
              )}

              {/* Risk Reasons */}
              {ace.risk_reasons.length > 0 && (
                <div>
                  <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Risk Analysis
                  </h4>
                  <ul className="space-y-1.5">
                    {ace.risk_reasons.map((reason, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm">
                        <AlertTriangle className={`mt-0.5 h-3.5 w-3.5 flex-shrink-0 ${config.color}`} />
                        <span className="text-foreground/80">{reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  )
}

function RecommendationCard({ recommendation }: { recommendation: SecurityRecommendation }) {
  const [isOpen, setIsOpen] = useState(recommendation.priority === "Critical")
  const config = riskLevelConfig[recommendation.priority]
  const RiskIcon = config.icon

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <Card className={`border ${config.bg}`}>
        <CollapsibleTrigger className="w-full">
          <CardHeader className="py-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`flex h-8 w-8 items-center justify-center rounded-lg ${config.bg}`}>
                  <RiskIcon className={`h-4 w-4 ${config.color}`} />
                </div>
                <div className="text-left">
                  <CardTitle className="text-sm font-medium text-foreground">{recommendation.title}</CardTitle>
                  {recommendation.affected_trustee && (
                    <CardDescription className="text-xs">Affects: {recommendation.affected_trustee}</CardDescription>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <RiskBadge level={recommendation.priority} />
                {isOpen ? (
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                )}
              </div>
            </div>
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="border-t border-border pt-4">
            <div className="space-y-4">
              <p className="text-sm text-foreground/80">{recommendation.description}</p>
              <div>
                <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Remediation Steps
                </h4>
                <ol className="space-y-2">
                  {recommendation.remediation_steps.map((step, i) => (
                    <li key={i} className="flex items-start gap-3 text-sm">
                      <span className="flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-primary/20 text-xs font-medium text-primary">
                        {i + 1}
                      </span>
                      <span className="text-foreground/80">{step}</span>
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  )
}

export function AdminSDHolderAnalysisView({ isConnected }: AdminSDHolderAnalysisProps) {
  const [analysis, setAnalysis] = useState<AdminSDHolderAnalysis | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<"overview" | "aces" | "recommendations">("overview")

  const handleAnalyze = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const result = await analyzeAdminSDHolder()
      setAnalysis(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to analyze AdminSDHolder")
    } finally {
      setIsLoading(false)
    }
  }

  if (!isConnected) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <Shield className="mb-4 h-12 w-12 text-muted-foreground" />
          <h3 className="mb-2 text-lg font-semibold text-foreground">Connect to Active Directory</h3>
          <p className="mb-4 text-center text-sm text-muted-foreground">
            Please connect to Active Directory to analyze AdminSDHolder permissions.
          </p>
        </CardContent>
      </Card>
    )
  }

  if (!analysis && !isLoading) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12">
          <ShieldAlert className="mb-4 h-12 w-12 text-primary" />
          <h3 className="mb-2 text-lg font-semibold text-foreground">AdminSDHolder Security Analysis</h3>
          <p className="mb-6 max-w-md text-center text-sm text-muted-foreground">
            Analyze the AdminSDHolder object to identify risky permissions that could lead to privilege escalation or
            unauthorized access to protected accounts.
          </p>
          <Button onClick={handleAnalyze} className="gap-2">
            <Shield className="h-4 w-4" />
            Start Security Analysis
          </Button>
        </CardContent>
      </Card>
    )
  }

  if (isLoading) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12">
          <Loader2 className="mb-4 h-12 w-12 animate-spin text-primary" />
          <h3 className="mb-2 text-lg font-semibold text-foreground">Analyzing AdminSDHolder...</h3>
          <p className="text-sm text-muted-foreground">Retrieving security descriptors and evaluating permissions</p>
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card className="border-destructive/50">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <XCircle className="mb-4 h-12 w-12 text-destructive" />
          <h3 className="mb-2 text-lg font-semibold text-foreground">Analysis Failed</h3>
          <p className="mb-4 text-center text-sm text-muted-foreground">{error}</p>
          <Button onClick={handleAnalyze} variant="outline" className="gap-2 bg-transparent">
            <RefreshCw className="h-4 w-4" />
            Retry Analysis
          </Button>
        </CardContent>
      </Card>
    )
  }

  const riskConfig = riskLevelConfig[analysis!.risk_summary.overall_risk]
  const RiskIcon = riskConfig.icon

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-foreground">AdminSDHolder Security Analysis</h2>
          <p className="text-sm text-muted-foreground">
            Analyzed: {new Date(analysis!.analysis_timestamp).toLocaleString()}
          </p>
        </div>
        <Button onClick={handleAnalyze} variant="outline" className="gap-2 bg-transparent">
          <RefreshCw className="h-4 w-4" />
          Re-analyze
        </Button>
      </div>

      {/* Risk Summary Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card className={`border ${riskConfig.bg}`}>
          <CardHeader className="pb-2">
            <CardDescription>Overall Risk</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <RiskIcon className={`h-5 w-5 ${riskConfig.color}`} />
              <span className={`text-2xl font-bold ${riskConfig.color}`}>{analysis!.risk_summary.overall_risk}</span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">Score: {analysis!.risk_summary.risk_score}</p>
          </CardContent>
        </Card>

        <Card className="border-red-500/30 bg-red-500/10">
          <CardHeader className="pb-2">
            <CardDescription>Critical Issues</CardDescription>
          </CardHeader>
          <CardContent>
            <span className="text-2xl font-bold text-red-400">{analysis!.risk_summary.critical_count}</span>
            <Progress
              value={(analysis!.risk_summary.critical_count / Math.max(analysis!.total_aces, 1)) * 100}
              className="mt-2 h-1.5 bg-red-950"
            />
          </CardContent>
        </Card>

        <Card className="border-orange-500/30 bg-orange-500/10">
          <CardHeader className="pb-2">
            <CardDescription>High Risk</CardDescription>
          </CardHeader>
          <CardContent>
            <span className="text-2xl font-bold text-orange-400">{analysis!.risk_summary.high_count}</span>
            <Progress
              value={(analysis!.risk_summary.high_count / Math.max(analysis!.total_aces, 1)) * 100}
              className="mt-2 h-1.5 bg-orange-950"
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total ACEs</CardDescription>
          </CardHeader>
          <CardContent>
            <span className="text-2xl font-bold text-foreground">{analysis!.total_aces}</span>
            <p className="mt-1 text-xs text-muted-foreground">{analysis!.risky_aces} require attention</p>
          </CardContent>
        </Card>
      </div>

      {/* Object Info */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Object Information</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 text-sm md:grid-cols-2">
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Distinguished Name:</span>
                <code className="max-w-[300px] truncate rounded bg-muted px-1.5 py-0.5 text-xs">
                  {analysis!.distinguished_name}
                </code>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Owner:</span>
                <span className="font-medium text-foreground">{analysis!.owner}</span>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Owner SID:</span>
                <code className="rounded bg-muted px-1.5 py-0.5 text-xs">{analysis!.owner_sid}</code>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Control Flags:</span>
                <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                  0x{analysis!.control_flags.toString(16).toUpperCase()}
                </code>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-border">
        <button
          onClick={() => setActiveTab("overview")}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === "overview"
              ? "border-b-2 border-primary text-primary"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Overview
        </button>
        <button
          onClick={() => setActiveTab("aces")}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === "aces"
              ? "border-b-2 border-primary text-primary"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Access Control Entries
          <Badge variant="secondary" className="text-xs">
            {analysis!.dacl_entries.length}
          </Badge>
        </button>
        <button
          onClick={() => setActiveTab("recommendations")}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === "recommendations"
              ? "border-b-2 border-primary text-primary"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Recommendations
          <Badge
            variant="secondary"
            className={analysis!.recommendations.length > 0 ? "bg-red-500/20 text-red-400" : ""}
          >
            {analysis!.recommendations.length}
          </Badge>
        </button>
      </div>

      {/* Tab Content */}
      <ScrollArea className="h-[500px]">
        {activeTab === "overview" && (
          <div className="space-y-4 pr-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Security Assessment Summary</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  The AdminSDHolder object defines the security template applied to all protected accounts and groups in
                  Active Directory. Any permissions on this object will be propagated to members of protected groups
                  (Domain Admins, Enterprise Admins, etc.) by the SDProp process every 60 minutes by default.
                </p>

                {analysis!.risk_summary.critical_count > 0 && (
                  <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4">
                    <div className="flex items-start gap-3">
                      <ShieldAlert className="mt-0.5 h-5 w-5 text-red-400" />
                      <div>
                        <h4 className="font-medium text-red-400">Critical Security Issues Detected</h4>
                        <p className="mt-1 text-sm text-foreground/80">
                          {analysis!.risk_summary.critical_count} critical permission issue(s) were found that could
                          allow privilege escalation to Domain Admin or compromise of all protected accounts. Immediate
                          remediation is recommended.
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                <div className="grid gap-4 md:grid-cols-2">
                  <div className="rounded-lg border bg-card p-4">
                    <h4 className="mb-2 text-sm font-medium text-foreground">Expected Trustees</h4>
                    <ul className="space-y-1 text-sm text-muted-foreground">
                      <li className="flex items-center gap-2">
                        <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                        BUILTIN\Administrators
                      </li>
                      <li className="flex items-center gap-2">
                        <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                        NT AUTHORITY\SYSTEM
                      </li>
                      <li className="flex items-center gap-2">
                        <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                        Domain Admins
                      </li>
                      <li className="flex items-center gap-2">
                        <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                        Enterprise Admins
                      </li>
                    </ul>
                  </div>
                  <div className="rounded-lg border bg-card p-4">
                    <h4 className="mb-2 text-sm font-medium text-foreground">Unexpected Trustees Found</h4>
                    <ul className="space-y-1 text-sm">
                      {analysis!.dacl_entries
                        .filter((ace) => ace.risk_level === "Critical" || ace.risk_level === "High")
                        .map((ace, i) => (
                          <li key={i} className="flex items-center gap-2">
                            <XCircle className="h-3.5 w-3.5 text-red-400" />
                            <span className="text-foreground/80">{ace.trustee}</span>
                          </li>
                        ))}
                      {analysis!.dacl_entries.filter(
                        (ace) => ace.risk_level === "Critical" || ace.risk_level === "High",
                      ).length === 0 && (
                        <li className="flex items-center gap-2 text-muted-foreground">
                          <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                          No unexpected trustees found
                        </li>
                      )}
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {activeTab === "aces" && (
          <div className="space-y-3 pr-4">
            {analysis!.dacl_entries.map((ace, index) => (
              <AceCard key={index} ace={ace} index={index} />
            ))}
          </div>
        )}

        {activeTab === "recommendations" && (
          <div className="space-y-3 pr-4">
            {analysis!.recommendations.length === 0 ? (
              <Card>
                <CardContent className="flex flex-col items-center justify-center py-8">
                  <ShieldCheck className="mb-3 h-10 w-10 text-green-400" />
                  <h3 className="text-lg font-medium text-foreground">No Issues Found</h3>
                  <p className="text-sm text-muted-foreground">
                    AdminSDHolder permissions appear to follow security best practices.
                  </p>
                </CardContent>
              </Card>
            ) : (
              analysis!.recommendations.map((rec, index) => <RecommendationCard key={index} recommendation={rec} />)
            )}
          </div>
        )}
      </ScrollArea>
    </div>
  )
}
