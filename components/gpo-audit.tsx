"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  FileText,
  Link2,
  Users,
  FolderOpen,
  ChevronDown,
  ChevronUp,
  Copy,
  Server,
} from "lucide-react"
import { auditGPO, type GpoAudit, type GroupPolicyObject, type SecurityFinding } from "@/lib/tauri-api"

interface GpoAuditViewProps {
  isConnected: boolean
}

export function GpoAuditView({ isConnected }: GpoAuditViewProps) {
  const [audit, setAudit] = useState<GpoAudit | null>(null)
  const [loading, setLoading] = useState(false)
  const [expandedGpos, setExpandedGpos] = useState<Set<string>>(new Set())
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set())
  const [error, setError] = useState<string | null>(null)

  const runAudit = async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await auditGPO()
      setAudit(result)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      setError(errorMessage)
      console.error("Failed to run GPO audit:", err)
    } finally {
      setLoading(false)
    }
  }

  const toggleGpo = (id: string) => {
    const newExpanded = new Set(expandedGpos)
    if (newExpanded.has(id)) {
      newExpanded.delete(id)
    } else {
      newExpanded.add(id)
    }
    setExpandedGpos(newExpanded)
  }

  const toggleFinding = (id: string) => {
    const newExpanded = new Set(expandedFindings)
    if (newExpanded.has(id)) {
      newExpanded.delete(id)
    } else {
      newExpanded.add(id)
    }
    setExpandedFindings(newExpanded)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "bg-red-500/20 text-red-400 border-red-500/30"
      case "High":
        return "bg-orange-500/20 text-orange-400 border-orange-500/30"
      case "Medium":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
      case "Low":
        return "bg-blue-500/20 text-blue-400 border-blue-500/30"
      default:
        return "bg-muted text-muted-foreground border-border"
    }
  }

  const getRiskLevelColor = (level: string) => {
    switch (level) {
      case "Critical":
        return "text-red-400"
      case "High":
        return "text-orange-400"
      case "Medium":
        return "text-yellow-400"
      case "Low":
        return "text-green-400"
      default:
        return "text-muted-foreground"
    }
  }

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  if (!isConnected) {
    return (
      <div className="flex h-full items-center justify-center">
        <Card className="w-full max-w-md border-border bg-card">
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FileText className="mb-4 h-16 w-16 text-muted-foreground" />
            <h3 className="mb-2 text-lg font-semibold text-foreground">Connect to Active Directory</h3>
            <p className="text-center text-sm text-muted-foreground">
              Please connect to Active Directory to run the GPO security audit.
            </p>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (!audit) {
    return (
      <div className="flex h-full items-center justify-center">
        <Card className="w-full max-w-lg border-border bg-card">
          <CardHeader className="text-center">
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
              <FileText className="h-8 w-8 text-primary" />
            </div>
            <CardTitle className="text-foreground">Group Policy Audit</CardTitle>
            <CardDescription>
              Evaluate your Group Policy Objects (GPOs) for security misconfigurations, over-permissioned policies, and
              SYSVOL permission issues.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col items-center">
            <Button onClick={runAudit} disabled={loading} size="lg">
              {loading ? (
                <>
                  <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                  Running Audit...
                </>
              ) : (
                <>
                  <FileText className="mr-2 h-4 w-4" />
                  Start GPO Audit
                </>
              )}
            </Button>
            {error && (
              <Alert className="mt-4 border-destructive/50 bg-destructive/10">
                <AlertTriangle className="h-4 w-4 text-destructive" />
                <AlertTitle className="text-destructive">Audit Failed</AlertTitle>
                <AlertDescription className="text-destructive/80">{error}</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Group Policy Audit</h2>
          <p className="text-sm text-muted-foreground">
            {audit.domain_name} - Last scanned: {new Date(audit.audit_timestamp).toLocaleString()}
          </p>
        </div>
        <Button onClick={runAudit} disabled={loading} variant="outline">
          {loading ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
          Re-run Audit
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-6">
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Risk Score</p>
                <p className={`text-3xl font-bold ${getRiskLevelColor(audit.risk_level)}`}>
                  {audit.overall_risk_score}
                </p>
              </div>
              <AlertTriangle className={`h-8 w-8 ${getRiskLevelColor(audit.risk_level)}`} />
            </div>
            <Badge className={`mt-2 ${getSeverityColor(audit.risk_level)}`}>{audit.risk_level}</Badge>
          </CardContent>
        </Card>

        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="text-center">
              <p className="text-sm text-muted-foreground">Total GPOs</p>
              <p className="text-3xl font-bold text-foreground">{audit.summary.total_gpos}</p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-red-500/20 bg-card">
          <CardContent className="pt-6">
            <div className="text-center">
              <p className="text-sm text-muted-foreground">Critical</p>
              <p className="text-3xl font-bold text-red-400">{audit.critical_count}</p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-orange-500/20 bg-card">
          <CardContent className="pt-6">
            <div className="text-center">
              <p className="text-sm text-muted-foreground">High</p>
              <p className="text-3xl font-bold text-orange-400">{audit.high_count}</p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-yellow-500/20 bg-card">
          <CardContent className="pt-6">
            <div className="text-center">
              <p className="text-sm text-muted-foreground">Unlinked</p>
              <p className="text-3xl font-bold text-yellow-400">{audit.summary.unlinked_gpos}</p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-purple-500/20 bg-card">
          <CardContent className="pt-6">
            <div className="text-center">
              <p className="text-sm text-muted-foreground">DC-Linked</p>
              <p className="text-3xl font-bold text-purple-400">{audit.summary.gpos_linked_to_dc_ou}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Warning Banner for DC issues */}
      {audit.summary.gpos_with_weak_dc_permissions > 0 && (
        <Alert className="border-red-500/30 bg-red-500/10">
          <XCircle className="h-4 w-4 text-red-400" />
          <AlertTitle className="text-red-400">Critical: Domain Controller GPO Permissions</AlertTitle>
          <AlertDescription className="text-red-300/80">
            {audit.summary.gpos_with_weak_dc_permissions} GPO(s) linked to Domain Controllers have weak permissions.
            This could allow non-admin users to compromise your Domain Controllers.
          </AlertDescription>
        </Alert>
      )}

      {/* Tabs */}
      <Tabs defaultValue="findings" className="space-y-4">
        <TabsList className="bg-muted">
          <TabsTrigger value="findings">
            <AlertTriangle className="mr-2 h-4 w-4" />
            Findings ({audit.total_findings})
          </TabsTrigger>
          <TabsTrigger value="gpos">
            <FileText className="mr-2 h-4 w-4" />
            All GPOs ({audit.gpos.length})
          </TabsTrigger>
          <TabsTrigger value="sysvol">
            <FolderOpen className="mr-2 h-4 w-4" />
            SYSVOL Permissions
          </TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-4">
          {audit.findings.length === 0 ? (
            <Alert className="border-green-500/30 bg-green-500/10">
              <CheckCircle2 className="h-4 w-4 text-green-400" />
              <AlertTitle className="text-green-400">No Issues Found</AlertTitle>
              <AlertDescription className="text-green-300/80">
                Your Group Policy configuration meets all evaluated security criteria.
              </AlertDescription>
            </Alert>
          ) : (
            <div className="space-y-3">
              {audit.findings
                .sort((a, b) => b.severity_level - a.severity_level)
                .map((finding) => (
                  <GpoFindingCard
                    key={finding.id}
                    finding={finding}
                    expanded={expandedFindings.has(finding.id)}
                    onToggle={() => toggleFinding(finding.id)}
                    getSeverityColor={getSeverityColor}
                    copyText={copyText}
                  />
                ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="gpos" className="space-y-4">
          <div className="space-y-3">
            {audit.gpos.map((gpo) => (
              <GpoCard
                key={gpo.id}
                gpo={gpo}
                expanded={expandedGpos.has(gpo.id)}
                onToggle={() => toggleGpo(gpo.id)}
                findings={audit.findings.filter((f) => f.affected_object === gpo.display_name)}
                getSeverityColor={getSeverityColor}
              />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="sysvol" className="space-y-4">
          <Card className="border-border bg-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-foreground">
                <FolderOpen className="h-5 w-5" />
                SYSVOL Permissions
              </CardTitle>
              <CardDescription>{audit.sysvol_path}</CardDescription>
            </CardHeader>
            <CardContent>
              {audit.summary.sysvol_permission_issues > 0 ? (
                <Alert className="mb-4 border-red-500/30 bg-red-500/10">
                  <XCircle className="h-4 w-4 text-red-400" />
                  <AlertTitle className="text-red-400">Permission Issues Detected</AlertTitle>
                  <AlertDescription className="text-red-300/80">
                    {audit.summary.sysvol_permission_issues} dangerous permission(s) found on SYSVOL.
                  </AlertDescription>
                </Alert>
              ) : (
                <Alert className="mb-4 border-green-500/30 bg-green-500/10">
                  <CheckCircle2 className="h-4 w-4 text-green-400" />
                  <AlertTitle className="text-green-400">Permissions Look Good</AlertTitle>
                  <AlertDescription className="text-green-300/80">
                    No dangerous SYSVOL permissions detected.
                  </AlertDescription>
                </Alert>
              )}

              <div className="space-y-2">
                {audit.sysvol_permissions.map((perm, idx) => (
                  <div
                    key={idx}
                    className={`flex items-center justify-between rounded-lg border p-3 ${
                      perm.is_dangerous ? "border-red-500/30 bg-red-500/5" : "border-border bg-muted/30"
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <Users className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium text-foreground">{perm.identity}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={perm.access_type === "Allow" ? "default" : "destructive"}>
                        {perm.access_type}
                      </Badge>
                      <Badge variant="outline">{perm.rights}</Badge>
                      {perm.is_dangerous && <Badge className="bg-red-500/20 text-red-400">Dangerous</Badge>}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

interface GpoCardProps {
  gpo: GroupPolicyObject
  expanded: boolean
  onToggle: () => void
  findings: SecurityFinding[]
  getSeverityColor: (severity: string) => string
}

function GpoCard({ gpo, expanded, onToggle, findings, getSeverityColor }: GpoCardProps) {
  const hasIssues = findings.length > 0
  const isLinkedToDC = gpo.links.some((l) => l.ou_distinguished_name.toLowerCase().includes("ou=domain controllers"))

  return (
    <Card className={`border-border bg-card ${hasIssues ? "border-orange-500/30" : ""}`}>
      <CardHeader className="cursor-pointer transition-colors hover:bg-muted/30" onClick={onToggle}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <FileText className="h-5 w-5 text-muted-foreground" />
            <div>
              <CardTitle className="text-base text-foreground">{gpo.display_name}</CardTitle>
              <p className="text-xs text-muted-foreground">{gpo.id}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isLinkedToDC && (
              <Badge className="bg-purple-500/20 text-purple-400">
                <Server className="mr-1 h-3 w-3" />
                DC-Linked
              </Badge>
            )}
            {gpo.links.length === 0 && <Badge variant="secondary">Unlinked</Badge>}
            {findings.length > 0 && (
              <Badge className={getSeverityColor(findings[0].severity)}>{findings.length} issue(s)</Badge>
            )}
            {expanded ? (
              <ChevronUp className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
        </div>
      </CardHeader>
      {expanded && (
        <CardContent className="space-y-4 border-t border-border pt-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Created</p>
              <p className="text-sm text-foreground">
                {gpo.created_time ? new Date(gpo.created_time).toLocaleString() : "Unknown"}
              </p>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Last Modified</p>
              <p className="text-sm text-foreground">
                {gpo.modified_time ? new Date(gpo.modified_time).toLocaleString() : "Unknown"}
              </p>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Owner</p>
              <p className="text-sm text-foreground">{gpo.owner}</p>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Settings</p>
              <div className="flex gap-2">
                {gpo.computer_settings_enabled && <Badge variant="outline">Computer</Badge>}
                {gpo.user_settings_enabled && <Badge variant="outline">User</Badge>}
              </div>
            </div>
          </div>

          {/* Links */}
          <div>
            <h4 className="mb-2 text-sm font-medium text-foreground">
              <Link2 className="mr-1 inline h-4 w-4" />
              Links ({gpo.links.length})
            </h4>
            {gpo.links.length === 0 ? (
              <p className="text-sm text-muted-foreground">Not linked to any OU</p>
            ) : (
              <div className="space-y-1">
                {gpo.links.map((link, idx) => (
                  <div key={idx} className="flex items-center justify-between rounded bg-muted/30 px-3 py-2 text-sm">
                    <span className="text-foreground">{link.ou_name}</span>
                    <div className="flex gap-2">
                      {link.enforced && <Badge className="bg-blue-500/20 text-blue-400">Enforced</Badge>}
                      {!link.link_enabled && <Badge variant="secondary">Disabled</Badge>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Permissions */}
          <div>
            <h4 className="mb-2 text-sm font-medium text-foreground">
              <Users className="mr-1 inline h-4 w-4" />
              Permissions ({gpo.permissions.length})
            </h4>
            <div className="space-y-1">
              {gpo.permissions.map((perm, idx) => {
                const isDangerous =
                  (perm.permission === "GpoEdit" || perm.permission === "GpoEditDeleteModifySecurity") &&
                  !["Domain Admins", "Enterprise Admins", "SYSTEM"].some((p) => perm.trustee.includes(p))
                return (
                  <div
                    key={idx}
                    className={`flex items-center justify-between rounded px-3 py-2 text-sm ${
                      isDangerous ? "bg-orange-500/10" : "bg-muted/30"
                    }`}
                  >
                    <span className={isDangerous ? "text-orange-400" : "text-foreground"}>{perm.trustee}</span>
                    <Badge variant={isDangerous ? "destructive" : "outline"}>{perm.permission_name}</Badge>
                  </div>
                )
              })}
            </div>
          </div>
        </CardContent>
      )}
    </Card>
  )
}

interface GpoFindingCardProps {
  finding: SecurityFinding
  expanded: boolean
  onToggle: () => void
  getSeverityColor: (severity: string) => string
  copyText: (text: string) => void
}

function GpoFindingCard({ finding, expanded, onToggle, getSeverityColor, copyText }: GpoFindingCardProps) {
  return (
    <Card className={`border-border bg-card ${finding.severity === "Critical" ? "border-red-500/30" : ""}`}>
      <CardHeader className="cursor-pointer transition-colors hover:bg-muted/30" onClick={onToggle}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Badge className={getSeverityColor(finding.severity)}>{finding.severity}</Badge>
            <Badge variant="outline">{finding.category}</Badge>
          </div>
          {expanded ? (
            <ChevronUp className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
        <CardTitle className="text-lg text-foreground">{finding.issue}</CardTitle>
        <CardDescription>{finding.affected_object}</CardDescription>
      </CardHeader>
      {expanded && (
        <CardContent className="space-y-4 border-t border-border pt-4">
          <div>
            <h4 className="mb-1 text-sm font-medium text-foreground">Description</h4>
            <p className="text-sm text-muted-foreground">{finding.description}</p>
          </div>
          <div>
            <h4 className="mb-1 text-sm font-medium text-foreground">Impact</h4>
            <p className="text-sm text-muted-foreground">{finding.impact}</p>
          </div>
          <div>
            <h4 className="mb-1 text-sm font-medium text-foreground">Remediation</h4>
            <div className="flex items-start gap-2">
              <code className="flex-1 rounded bg-muted p-2 text-xs text-foreground">{finding.remediation}</code>
              <Button
                variant="ghost"
                size="icon"
                className="shrink-0"
                onClick={(e) => {
                  e.stopPropagation()
                  copyText(finding.remediation)
                }}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardContent>
      )}
    </Card>
  )
}
