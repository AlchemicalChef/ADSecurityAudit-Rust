/**
 * Privileged Group Membership Audit Component
 *
 * Analyzes membership of privileged Active Directory groups to identify
 * security issues such as excessive membership and stale accounts.
 *
 * @module components/group-audit
 *
 * Groups Analyzed:
 * - Critical: Domain Admins, Enterprise Admins, Schema Admins, Administrators
 * - Protected: Backup Operators, Account Operators, Server Operators
 * - Service: DnsAdmins, Cert Publishers, Key Admins
 *
 * Issues Detected:
 * - Excessive membership (exceeds recommended thresholds)
 * - Nested groups in critical groups (obscures actual membership)
 * - Disabled users still in privileged groups
 * - Inactive users (no login > 90 days)
 *
 * Membership Thresholds:
 * - Critical groups: Maximum 5 members recommended
 * - Protected groups: Maximum 15 members recommended
 *
 * Best Practices Checked:
 * - Direct membership only in Tier 0 groups
 * - Regular access reviews
 * - Just-In-Time (JIT) privileged access
 * - Automated offboarding cleanup
 *
 * @see https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory
 */
"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
  Users,
  AlertTriangle,
  Shield,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  UserX,
  Clock,
  GitBranch,
  Copy,
  CheckCircle2,
} from "lucide-react"
import { auditPrivilegedGroups, type GroupAudit, type GroupFinding, type PrivilegedGroupInfo } from "@/lib/tauri-api"

interface GroupAuditViewProps {
  isConnected: boolean
}

export function GroupAuditView({ isConnected }: GroupAuditViewProps) {
  const [audit, setAudit] = useState<GroupAudit | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set())
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null)

  const runAudit = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const result = await auditPrivilegedGroups()
      setAudit(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run audit")
    } finally {
      setIsLoading(false)
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

  const toggleGroup = (name: string) => {
    const newExpanded = new Set(expandedGroups)
    if (newExpanded.has(name)) {
      newExpanded.delete(name)
    } else {
      newExpanded.add(name)
    }
    setExpandedGroups(newExpanded)
  }

  const copyToClipboard = async (text: string, id: string) => {
    await navigator.clipboard.writeText(text)
    setCopiedCommand(id)
    setTimeout(() => setCopiedCommand(null), 2000)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-500/20 text-red-400 border-red-500/30"
      case "high":
        return "bg-orange-500/20 text-orange-400 border-orange-500/30"
      case "medium":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
      case "low":
        return "bg-blue-500/20 text-blue-400 border-blue-500/30"
      default:
        return "bg-muted text-muted-foreground"
    }
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
          <Users className="mb-4 h-12 w-12 text-muted-foreground" />
          <h3 className="mb-2 text-lg font-medium text-foreground">Not Connected</h3>
          <p className="text-center text-sm text-muted-foreground">
            Connect to Active Directory to audit privileged group memberships
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Privileged Group Audit</h2>
          <p className="text-sm text-muted-foreground">Analyze privileged group memberships for security risks</p>
        </div>
        <Button onClick={runAudit} disabled={isLoading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
          {isLoading ? "Scanning..." : "Run Audit"}
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {audit && (
        <>
          {/* Summary Cards */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
            <Card className="border-border bg-card">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-muted-foreground">Risk Score</p>
                    <p className={`text-2xl font-bold ${getRiskScoreColor(audit.risk_score)}`}>
                      {audit.risk_score}/100
                    </p>
                  </div>
                  <Shield className={`h-8 w-8 ${getRiskScoreColor(audit.risk_score)}`} />
                </div>
              </CardContent>
            </Card>

            <Card className="border-border bg-card">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-muted-foreground">Excessive Membership</p>
                    <p className="text-2xl font-bold text-orange-400">{audit.excessive_membership_count}</p>
                  </div>
                  <Users className="h-8 w-8 text-orange-400" />
                </div>
              </CardContent>
            </Card>

            <Card className="border-border bg-card">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-muted-foreground">Nested Groups</p>
                    <p className="text-2xl font-bold text-yellow-400">{audit.nested_groups_count}</p>
                  </div>
                  <GitBranch className="h-8 w-8 text-yellow-400" />
                </div>
              </CardContent>
            </Card>

            <Card className="border-border bg-card">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-muted-foreground">Disabled Users</p>
                    <p className="text-2xl font-bold text-red-400">{audit.disabled_users_count}</p>
                  </div>
                  <UserX className="h-8 w-8 text-red-400" />
                </div>
              </CardContent>
            </Card>

            <Card className="border-border bg-card">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-muted-foreground">Inactive Users</p>
                    <p className="text-2xl font-bold text-blue-400">{audit.inactive_users_count}</p>
                  </div>
                  <Clock className="h-8 w-8 text-blue-400" />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Tabs */}
          <Tabs defaultValue="findings" className="w-full">
            <TabsList className="bg-muted">
              <TabsTrigger value="findings">Findings ({audit.findings.length})</TabsTrigger>
              <TabsTrigger value="groups">Groups ({audit.groups.length})</TabsTrigger>
              <TabsTrigger value="recommendations">Recommendations ({audit.recommendations.length})</TabsTrigger>
            </TabsList>

            <TabsContent value="findings" className="mt-4 space-y-3">
              {audit.findings.length === 0 ? (
                <Card className="border-border bg-card">
                  <CardContent className="flex items-center justify-center py-8">
                    <CheckCircle2 className="mr-2 h-5 w-5 text-green-400" />
                    <span className="text-muted-foreground">No issues found in privileged groups</span>
                  </CardContent>
                </Card>
              ) : (
                audit.findings.map((finding, index) => (
                  <FindingCard
                    key={index}
                    finding={finding}
                    index={index}
                    isExpanded={expandedFindings.has(`finding-${index}`)}
                    onToggle={() => toggleFinding(`finding-${index}`)}
                    getSeverityColor={getSeverityColor}
                    onCopy={copyToClipboard}
                    copiedCommand={copiedCommand}
                  />
                ))
              )}
            </TabsContent>

            <TabsContent value="groups" className="mt-4 space-y-3">
              {audit.groups.map((group) => (
                <GroupCard
                  key={group.name}
                  group={group}
                  isExpanded={expandedGroups.has(group.name)}
                  onToggle={() => toggleGroup(group.name)}
                />
              ))}
            </TabsContent>

            <TabsContent value="recommendations" className="mt-4 space-y-3">
              {audit.recommendations.map((rec, index) => (
                <Card key={index} className="border-border bg-card">
                  <CardHeader className="pb-2">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="bg-primary/10 text-primary">
                        Priority {rec.priority}
                      </Badge>
                      <CardTitle className="text-base">{rec.title}</CardTitle>
                    </div>
                    <CardDescription>{rec.description}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ol className="list-decimal space-y-1 pl-4 text-sm text-muted-foreground">
                      {rec.steps.map((step, stepIndex) => (
                        <li key={stepIndex} className="font-mono text-xs">
                          {step}
                        </li>
                      ))}
                    </ol>
                  </CardContent>
                </Card>
              ))}
            </TabsContent>
          </Tabs>
        </>
      )}
    </div>
  )
}

function FindingCard({
  finding,
  index,
  isExpanded,
  onToggle,
  getSeverityColor,
  onCopy,
  copiedCommand,
}: {
  finding: GroupFinding
  index: number
  isExpanded: boolean
  onToggle: () => void
  getSeverityColor: (severity: string) => string
  onCopy: (text: string, id: string) => void
  copiedCommand: string | null
}) {
  return (
    <Collapsible open={isExpanded} onOpenChange={onToggle}>
      <Card
        className={`border-l-4 ${finding.severity === "Critical" ? "border-l-red-500" : finding.severity === "High" ? "border-l-orange-500" : finding.severity === "Medium" ? "border-l-yellow-500" : "border-l-blue-500"} border-border bg-card`}
      >
        <CollapsibleTrigger asChild>
          <CardHeader className="cursor-pointer pb-2 hover:bg-accent/50">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {isExpanded ? (
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                )}
                <Badge className={getSeverityColor(finding.severity)}>{finding.severity}</Badge>
                <span className="font-medium text-foreground">{finding.issue}</span>
              </div>
              <span className="text-sm text-muted-foreground">{finding.affected_object}</span>
            </div>
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="space-y-4 pt-0">
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
              <div className="relative">
                <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs text-muted-foreground">
                  {finding.remediation}
                </pre>
                <Button
                  variant="ghost"
                  size="sm"
                  className="absolute right-2 top-2"
                  onClick={() => onCopy(finding.remediation, `finding-${index}`)}
                >
                  {copiedCommand === `finding-${index}` ? (
                    <CheckCircle2 className="h-4 w-4 text-green-400" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </Button>
              </div>
            </div>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  )
}

function GroupCard({
  group,
  isExpanded,
  onToggle,
}: {
  group: PrivilegedGroupInfo
  isExpanded: boolean
  onToggle: () => void
}) {
  const hasIssues =
    group.member_count > group.threshold ||
    group.nested_groups.length > 0 ||
    group.disabled_users.length > 0 ||
    group.inactive_users.length > 0

  return (
    <Collapsible open={isExpanded} onOpenChange={onToggle}>
      <Card className={`border-border bg-card ${hasIssues ? "border-l-4 border-l-orange-500" : ""}`}>
        <CollapsibleTrigger asChild>
          <CardHeader className="cursor-pointer pb-2 hover:bg-accent/50">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {isExpanded ? (
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                )}
                <Users className="h-4 w-4 text-primary" />
                <span className="font-medium text-foreground">{group.name}</span>
                {group.is_critical && (
                  <Badge variant="destructive" className="text-xs">
                    Critical Group
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-4 text-sm">
                <span className={group.member_count > group.threshold ? "text-orange-400" : "text-muted-foreground"}>
                  {group.member_count} / {group.threshold} members
                </span>
              </div>
            </div>
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="space-y-4 pt-0">
            <div className="grid gap-4 md:grid-cols-3">
              {group.nested_groups.length > 0 && (
                <div>
                  <h4 className="mb-2 flex items-center gap-2 text-sm font-medium text-yellow-400">
                    <GitBranch className="h-4 w-4" />
                    Nested Groups ({group.nested_groups.length})
                  </h4>
                  <ul className="space-y-1 text-sm text-muted-foreground">
                    {group.nested_groups.map((g) => (
                      <li key={g.sam_account_name}>{g.sam_account_name}</li>
                    ))}
                  </ul>
                </div>
              )}
              {group.disabled_users.length > 0 && (
                <div>
                  <h4 className="mb-2 flex items-center gap-2 text-sm font-medium text-red-400">
                    <UserX className="h-4 w-4" />
                    Disabled Users ({group.disabled_users.length})
                  </h4>
                  <ul className="space-y-1 text-sm text-muted-foreground">
                    {group.disabled_users.map((u) => (
                      <li key={u.sam_account_name}>{u.sam_account_name}</li>
                    ))}
                  </ul>
                </div>
              )}
              {group.inactive_users.length > 0 && (
                <div>
                  <h4 className="mb-2 flex items-center gap-2 text-sm font-medium text-blue-400">
                    <Clock className="h-4 w-4" />
                    Inactive Users ({group.inactive_users.length})
                  </h4>
                  <ul className="space-y-1 text-sm text-muted-foreground">
                    {group.inactive_users.map((u) => (
                      <li key={u.sam_account_name}>{u.sam_account_name}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
            {!hasIssues && (
              <div className="flex items-center gap-2 text-sm text-green-400">
                <CheckCircle2 className="h-4 w-4" />
                No issues detected for this group
              </div>
            )}
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  )
}
