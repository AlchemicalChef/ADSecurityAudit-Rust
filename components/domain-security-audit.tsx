/** Domain Security Audit -- evaluates domain-level settings, password policies, and functional levels. */
"use client"

import type React from "react"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Lock,
  Server,
  Key,
  Monitor,
  Cloud,
  Recycle,
  ChevronDown,
  ChevronUp,
  Copy,
  ExternalLink,
} from "lucide-react"
import { auditDomainSecurity, type DomainSecurityAudit, type SecurityFinding } from "@/lib/tauri-api"

interface DomainSecurityAuditProps {
  isConnected: boolean
}

export function DomainSecurityAuditView({ isConnected }: DomainSecurityAuditProps) {
  const [audit, setAudit] = useState<DomainSecurityAudit | null>(null)
  const [loading, setLoading] = useState(false)
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set())

  const runAudit = async () => {
    setLoading(true)
    try {
      const result = await auditDomainSecurity()
      setAudit(result)
    } catch (error) {
      // Audit failure; loading state reset in finally block
    } finally {
      setLoading(false)
    }
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

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case "PasswordPolicy":
        return <Key className="h-4 w-4" />
      case "FunctionalLevel":
        return <Server className="h-4 w-4" />
      case "LegacySystems":
        return <Monitor className="h-4 w-4" />
      case "AzureADSSO":
        return <Cloud className="h-4 w-4" />
      case "RecycleBin":
        return <Recycle className="h-4 w-4" />
      default:
        return <Shield className="h-4 w-4" />
    }
  }

  const copyRemediation = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  if (!isConnected) {
    return (
      <div className="flex h-full items-center justify-center">
        <Card className="w-full max-w-md border-border bg-card">
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Shield className="mb-4 h-16 w-16 text-muted-foreground" />
            <h3 className="mb-2 text-lg font-semibold text-foreground">Connect to Active Directory</h3>
            <p className="text-center text-sm text-muted-foreground">
              Please connect to Active Directory to run the domain security audit.
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
              <Shield className="h-8 w-8 text-primary" />
            </div>
            <CardTitle className="text-foreground">Domain Security Audit</CardTitle>
            <CardDescription>
              Evaluate your Active Directory domain security settings including password policies, functional levels,
              legacy systems, and Azure AD SSO configuration.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            <Button onClick={runAudit} disabled={loading} size="lg">
              {loading ? (
                <>
                  <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                  Running Audit...
                </>
              ) : (
                <>
                  <Shield className="mr-2 h-4 w-4" />
                  Start Security Audit
                </>
              )}
            </Button>
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
          <h2 className="text-2xl font-bold text-foreground">Domain Security Audit</h2>
          <p className="text-sm text-muted-foreground">
            {audit.domain_dns_root} - Last scanned: {new Date(audit.audit_timestamp).toLocaleString()}
          </p>
        </div>
        <Button onClick={runAudit} disabled={loading} variant="outline">
          {loading ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
          Re-run Audit
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-5">
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Risk Score</p>
                <p className={`text-3xl font-bold ${getRiskLevelColor(audit.risk_level)}`}>
                  {audit.overall_risk_score}
                </p>
              </div>
              <div
                className={`rounded-full p-3 ${audit.risk_level === "Critical" || audit.risk_level === "High" ? "bg-red-500/10" : "bg-yellow-500/10"}`}
              >
                <AlertTriangle className={`h-6 w-6 ${getRiskLevelColor(audit.risk_level)}`} />
              </div>
            </div>
            <Badge className={`mt-2 ${getSeverityColor(audit.risk_level)}`}>{audit.risk_level} Risk</Badge>
          </CardContent>
        </Card>

        <Card className="border-red-500/20 bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Critical</p>
                <p className="text-3xl font-bold text-red-400">{audit.critical_count}</p>
              </div>
              <XCircle className="h-8 w-8 text-red-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-orange-500/20 bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">High</p>
                <p className="text-3xl font-bold text-orange-400">{audit.high_count}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-orange-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-yellow-500/20 bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Medium</p>
                <p className="text-3xl font-bold text-yellow-400">{audit.medium_count}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-yellow-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-blue-500/20 bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Low</p>
                <p className="text-3xl font-bold text-blue-400">{audit.low_count}</p>
              </div>
              <CheckCircle2 className="h-8 w-8 text-blue-400" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="findings" className="space-y-4">
        <TabsList className="bg-muted">
          <TabsTrigger value="findings">Findings ({audit.total_findings})</TabsTrigger>
          <TabsTrigger value="password-policy">Password Policy</TabsTrigger>
          <TabsTrigger value="legacy-systems">Legacy Systems ({audit.legacy_computers.length})</TabsTrigger>
          <TabsTrigger value="azure-sso">Azure AD SSO</TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-4">
          {audit.findings.length === 0 ? (
            <Alert className="border-green-500/30 bg-green-500/10">
              <CheckCircle2 className="h-4 w-4 text-green-400" />
              <AlertTitle className="text-green-400">No Issues Found</AlertTitle>
              <AlertDescription className="text-green-300/80">
                Your domain security configuration meets all evaluated criteria.
              </AlertDescription>
            </Alert>
          ) : (
            <div className="space-y-3">
              {audit.findings
                .sort((a, b) => b.severity_level - a.severity_level)
                .map((finding) => (
                  <FindingCard
                    key={finding.id}
                    finding={finding}
                    expanded={expandedFindings.has(finding.id)}
                    onToggle={() => toggleFinding(finding.id)}
                    getSeverityColor={getSeverityColor}
                    getCategoryIcon={getCategoryIcon}
                    copyRemediation={copyRemediation}
                  />
                ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="password-policy" className="space-y-4">
          <Card className="border-border bg-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-foreground">
                <Lock className="h-5 w-5" />
                Default Domain Password Policy
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2">
                <PolicyItem
                  label="Minimum Password Length"
                  value={`${audit.password_policy.min_password_length} characters`}
                  status={audit.password_policy.min_password_length >= 14 ? "good" : "warning"}
                  recommendation="Recommended: 14+ characters"
                />
                <PolicyItem
                  label="Password History"
                  value={`${audit.password_policy.password_history_count} passwords`}
                  status={audit.password_policy.password_history_count >= 24 ? "good" : "warning"}
                  recommendation="Recommended: 24 passwords"
                />
                <PolicyItem
                  label="Max Password Age"
                  value={`${audit.password_policy.max_password_age_days} days`}
                  status={
                    audit.password_policy.max_password_age_days <= 90 && audit.password_policy.max_password_age_days > 0
                      ? "good"
                      : "warning"
                  }
                  recommendation="Recommended: 60-90 days"
                />
                <PolicyItem
                  label="Complexity Enabled"
                  value={audit.password_policy.complexity_enabled ? "Yes" : "No"}
                  status={audit.password_policy.complexity_enabled ? "good" : "critical"}
                  recommendation="Should be enabled"
                />
                <PolicyItem
                  label="Reversible Encryption"
                  value={audit.password_policy.reversible_encryption_enabled ? "Yes" : "No"}
                  status={audit.password_policy.reversible_encryption_enabled ? "critical" : "good"}
                  recommendation="Should be disabled"
                />
                <PolicyItem
                  label="Lockout Threshold"
                  value={
                    audit.password_policy.lockout_threshold === 0
                      ? "Disabled"
                      : `${audit.password_policy.lockout_threshold} attempts`
                  }
                  status={
                    audit.password_policy.lockout_threshold > 0 && audit.password_policy.lockout_threshold <= 10
                      ? "good"
                      : "warning"
                  }
                  recommendation="Recommended: 3-5 attempts"
                />
              </div>
            </CardContent>
          </Card>

          <Card className="border-border bg-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-foreground">
                <Server className="h-5 w-5" />
                Domain Configuration
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Domain Functional Level</p>
                  <p className="font-medium text-foreground">{audit.domain_functional_level}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Forest Functional Level</p>
                  <p className="font-medium text-foreground">{audit.forest_functional_level}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">AD Recycle Bin</p>
                  <div className="flex items-center gap-2">
                    {audit.recycle_bin_enabled ? (
                      <CheckCircle2 className="h-4 w-4 text-green-400" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-400" />
                    )}
                    <p className={`font-medium ${audit.recycle_bin_enabled ? "text-green-400" : "text-red-400"}`}>
                      {audit.recycle_bin_enabled ? "Enabled" : "Disabled"}
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="legacy-systems" className="space-y-4">
          {audit.legacy_computers.length === 0 ? (
            <Alert className="border-green-500/30 bg-green-500/10">
              <CheckCircle2 className="h-4 w-4 text-green-400" />
              <AlertTitle className="text-green-400">No Legacy Systems Found</AlertTitle>
              <AlertDescription className="text-green-300/80">
                No computers running unsupported operating systems were detected.
              </AlertDescription>
            </Alert>
          ) : (
            <Card className="border-border bg-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-foreground">
                  <Monitor className="h-5 w-5" />
                  Legacy Operating Systems ({audit.legacy_computers.length})
                </CardTitle>
                <CardDescription>
                  Computers running unsupported operating systems that may pose security risks.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {audit.legacy_computers.map((computer, idx) => (
                    <div
                      key={idx}
                      className={`flex items-center justify-between rounded-lg border p-4 ${
                        computer.is_enabled ? "border-red-500/30 bg-red-500/5" : "border-border bg-muted/30"
                      }`}
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <Monitor className="h-4 w-4 text-muted-foreground" />
                          <p className="font-medium text-foreground">{computer.name}</p>
                          {computer.is_enabled ? (
                            <Badge className="bg-red-500/20 text-red-400">Active</Badge>
                          ) : (
                            <Badge variant="secondary">Disabled</Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground">{computer.operating_system}</p>
                        {computer.last_logon && (
                          <p className="text-xs text-muted-foreground">
                            Last logon: {new Date(computer.last_logon).toLocaleDateString()}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="azure-sso" className="space-y-4">
          {audit.azure_sso_accounts.length === 0 ? (
            <Alert className="border-muted bg-muted/30">
              <Cloud className="h-4 w-4" />
              <AlertTitle>No Azure AD SSO Accounts Found</AlertTitle>
              <AlertDescription>
                No AZUREADSSOACC$ computer accounts were detected. Azure AD Seamless SSO may not be configured.
              </AlertDescription>
            </Alert>
          ) : (
            <div className="space-y-4">
              {audit.azure_sso_accounts.map((account, idx) => (
                <Card
                  key={idx}
                  className={`border-border bg-card ${account.needs_rotation ? "border-orange-500/30" : ""}`}
                >
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-foreground">
                      <Cloud className="h-5 w-5" />
                      {account.sam_account_name}
                      {account.needs_rotation && (
                        <Badge className="bg-orange-500/20 text-orange-400">Rotation Needed</Badge>
                      )}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-1">
                        <p className="text-sm text-muted-foreground">Password Age</p>
                        <p className={`font-medium ${account.needs_rotation ? "text-orange-400" : "text-foreground"}`}>
                          {account.password_age_days} days
                        </p>
                      </div>
                      <div className="space-y-1">
                        <p className="text-sm text-muted-foreground">Last Password Change</p>
                        <p className="font-medium text-foreground">
                          {account.password_last_set
                            ? new Date(account.password_last_set).toLocaleDateString()
                            : "Unknown"}
                        </p>
                      </div>
                    </div>
                    {account.needs_rotation && (
                      <Alert className="mt-4 border-orange-500/30 bg-orange-500/10">
                        <AlertTriangle className="h-4 w-4 text-orange-400" />
                        <AlertTitle className="text-orange-400">Key Rotation Required</AlertTitle>
                        <AlertDescription className="text-orange-300/80">
                          The Kerberos decryption key should be rotated every 30 days.
                          <a
                            href="https://learn.microsoft.com/azure/active-directory/hybrid/tshoot-connect-sso"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="ml-1 inline-flex items-center text-primary hover:underline"
                          >
                            Learn more <ExternalLink className="ml-1 h-3 w-3" />
                          </a>
                        </AlertDescription>
                      </Alert>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}

interface PolicyItemProps {
  label: string
  value: string
  status: "good" | "warning" | "critical"
  recommendation: string
}

function PolicyItem({ label, value, status, recommendation }: PolicyItemProps) {
  const statusColors = {
    good: "text-green-400",
    warning: "text-yellow-400",
    critical: "text-red-400",
  }

  const StatusIcon = status === "good" ? CheckCircle2 : status === "warning" ? AlertTriangle : XCircle

  return (
    <div className="space-y-1 rounded-lg border border-border bg-muted/30 p-4">
      <p className="text-sm text-muted-foreground">{label}</p>
      <div className="flex items-center gap-2">
        <StatusIcon className={`h-4 w-4 ${statusColors[status]}`} />
        <p className={`font-medium ${statusColors[status]}`}>{value}</p>
      </div>
      <p className="text-xs text-muted-foreground">{recommendation}</p>
    </div>
  )
}

interface FindingCardProps {
  finding: SecurityFinding
  expanded: boolean
  onToggle: () => void
  getSeverityColor: (severity: string) => string
  getCategoryIcon: (category: string) => React.ReactNode
  copyRemediation: (text: string) => void
}

function FindingCard({
  finding,
  expanded,
  onToggle,
  getSeverityColor,
  getCategoryIcon,
  copyRemediation,
}: FindingCardProps) {
  return (
    <Card className={`border-border bg-card ${finding.severity === "Critical" ? "border-red-500/30" : ""}`}>
      <CardHeader className="cursor-pointer transition-colors hover:bg-muted/30" onClick={onToggle}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Badge className={getSeverityColor(finding.severity)}>{finding.severity}</Badge>
            <div className="flex items-center gap-2 text-muted-foreground">
              {getCategoryIcon(finding.category)}
              <span className="text-xs">{finding.category}</span>
            </div>
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
                  copyRemediation(finding.remediation)
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
