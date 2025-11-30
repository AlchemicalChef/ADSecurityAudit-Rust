"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
  AlertTriangle,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Lock,
  Key,
  Users,
  CheckCircle,
  Copy,
  XCircle,
  Folder,
} from "lucide-react"
import { auditPermissions, type PermissionsAudit } from "@/lib/tauri-api"

interface PermissionsAuditViewProps {
  isConnected: boolean
}

export function PermissionsAuditView({ isConnected }: PermissionsAuditViewProps) {
  const [audit, setAudit] = useState<PermissionsAudit | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set())
  const [expandedOus, setExpandedOus] = useState<Set<number>>(new Set())
  const [copiedText, setCopiedText] = useState<string | null>(null)

  const runAudit = async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await auditPermissions()
      setAudit(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run permissions audit")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (isConnected) {
      runAudit()
    }
  }, [isConnected])

  const toggleFinding = (index: number) => {
    const newExpanded = new Set(expandedFindings)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedFindings(newExpanded)
  }

  const toggleOu = (index: number) => {
    const newExpanded = new Set(expandedOus)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedOus(newExpanded)
  }

  const copyToClipboard = async (text: string) => {
    await navigator.clipboard.writeText(text)
    setCopiedText(text)
    setTimeout(() => setCopiedText(null), 2000)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-500/20 text-red-400 border-red-500/50"
      case "high":
        return "bg-orange-500/20 text-orange-400 border-orange-500/50"
      case "medium":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/50"
      case "low":
        return "bg-blue-500/20 text-blue-400 border-blue-500/50"
      default:
        return "bg-muted text-muted-foreground border-border"
    }
  }

  const getRiskLevel = (score: number): { label: string; color: string } => {
    if (score >= 70) return { label: "Critical", color: "text-red-400" }
    if (score >= 50) return { label: "High", color: "text-orange-400" }
    if (score >= 30) return { label: "Medium", color: "text-yellow-400" }
    return { label: "Low", color: "text-green-400" }
  }

  if (!isConnected) {
    return (
      <div className="flex h-full items-center justify-center">
        <Card className="max-w-md">
          <CardHeader className="text-center">
            <Lock className="mx-auto h-12 w-12 text-muted-foreground" />
            <CardTitle>Connection Required</CardTitle>
            <CardDescription>Connect to Active Directory to audit dangerous permissions.</CardDescription>
          </CardHeader>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Permissions Audit</h2>
          <p className="text-muted-foreground">Detect dangerous ACLs and over-privileged principals</p>
        </div>
        <Button onClick={runAudit} disabled={loading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          {loading ? "Scanning..." : "Run Audit"}
        </Button>
      </div>

      {/* Educational Alert */}
      <Alert className="border-red-500/50 bg-red-500/10">
        <Lock className="h-4 w-4 text-red-400" />
        <AlertTitle className="text-red-400">About Dangerous Permissions</AlertTitle>
        <AlertDescription className="text-red-300/80">
          Dangerous permissions like <strong>GenericAll</strong>, <strong>WriteDacl</strong>, and{" "}
          <strong>WriteOwner</strong> can be abused for privilege escalation. The <strong>Enterprise Key Admins</strong>{" "}
          misconfiguration (CVE) can grant unintended DCSync rights. Permissions on{" "}
          <strong>Domain Controllers OU</strong> are especially critical.
        </AlertDescription>
      </Alert>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {audit && (
        <>
          {/* Summary Cards */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
            <Card className="border-border bg-card">
              <CardHeader className="pb-2">
                <CardDescription>Total Findings</CardDescription>
                <CardTitle className="text-3xl">{audit.all_findings.length}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-red-500/30 bg-red-500/10">
              <CardHeader className="pb-2">
                <CardDescription className="text-red-400">Critical</CardDescription>
                <CardTitle className="text-3xl text-red-400">{audit.critical_findings}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-orange-500/30 bg-orange-500/10">
              <CardHeader className="pb-2">
                <CardDescription className="text-orange-400">High</CardDescription>
                <CardTitle className="text-3xl text-orange-400">{audit.high_findings}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-yellow-500/30 bg-yellow-500/10">
              <CardHeader className="pb-2">
                <CardDescription className="text-yellow-400">Medium</CardDescription>
                <CardTitle className="text-3xl text-yellow-400">{audit.medium_findings}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-blue-500/30 bg-blue-500/10">
              <CardHeader className="pb-2">
                <CardDescription className="text-blue-400">Low</CardDescription>
                <CardTitle className="text-3xl text-blue-400">{audit.low_findings}</CardTitle>
              </CardHeader>
            </Card>
          </div>

          {/* Enterprise Key Admins Status */}
          <Card
            className={`border ${audit.enterprise_key_admins.has_excessive_rights ? "border-red-500/50 bg-red-500/10" : "border-green-500/50 bg-green-500/10"}`}
          >
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Key
                    className={`h-6 w-6 ${audit.enterprise_key_admins.has_excessive_rights ? "text-red-400" : "text-green-400"}`}
                  />
                  <div>
                    <CardTitle>Enterprise Key Admins</CardTitle>
                    <CardDescription>
                      {audit.enterprise_key_admins.exists
                        ? `Group exists with ${audit.enterprise_key_admins.member_count} members`
                        : "Group not found (pre-2016 domain?)"}
                    </CardDescription>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {audit.enterprise_key_admins.has_excessive_rights ? (
                    <Badge className="bg-red-500/20 text-red-400">
                      <XCircle className="mr-1 h-3 w-3" />
                      Over-Privileged
                    </Badge>
                  ) : (
                    <Badge className="bg-green-500/20 text-green-400">
                      <CheckCircle className="mr-1 h-3 w-3" />
                      Properly Configured
                    </Badge>
                  )}
                  {audit.enterprise_key_admins.has_dcsync_capability && (
                    <Badge className="bg-red-500/20 text-red-400">DCSync Capable</Badge>
                  )}
                </div>
              </div>
            </CardHeader>
            {audit.enterprise_key_admins.has_excessive_rights && (
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  This is a known misconfiguration where Enterprise Key Admins was granted excessive permissions on the
                  domain root instead of just msDS-KeyCredentialLink access. This can enable DCSync attacks.
                </p>
              </CardContent>
            )}
          </Card>

          {/* Risk Score */}
          <Card className="border-border bg-card">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Overall Risk Assessment</CardTitle>
                  <CardDescription>Based on dangerous permissions found</CardDescription>
                </div>
                <div className="text-right">
                  <div className={`text-4xl font-bold ${getRiskLevel(audit.risk_score).color}`}>{audit.risk_score}</div>
                  <div className={`text-sm ${getRiskLevel(audit.risk_score).color}`}>
                    {getRiskLevel(audit.risk_score).label} Risk
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="h-3 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className={`h-full transition-all ${
                    audit.risk_score >= 70
                      ? "bg-red-500"
                      : audit.risk_score >= 50
                        ? "bg-orange-500"
                        : audit.risk_score >= 30
                          ? "bg-yellow-500"
                          : "bg-green-500"
                  }`}
                  style={{ width: `${Math.min(audit.risk_score, 100)}%` }}
                />
              </div>
            </CardContent>
          </Card>

          {/* Tabs */}
          <Tabs defaultValue="findings" className="space-y-4">
            <TabsList>
              <TabsTrigger value="findings">All Findings ({audit.all_findings.length})</TabsTrigger>
              <TabsTrigger value="critical-ous">Critical OUs ({audit.critical_ous.length})</TabsTrigger>
              <TabsTrigger value="recommendations">Recommendations ({audit.recommendations.length})</TabsTrigger>
            </TabsList>

            <TabsContent value="findings" className="space-y-4">
              {audit.all_findings.length === 0 ? (
                <Card className="border-green-500/30 bg-green-500/10">
                  <CardContent className="flex items-center gap-3 py-6">
                    <CheckCircle className="h-6 w-6 text-green-400" />
                    <p className="text-green-400">No dangerous permissions found.</p>
                  </CardContent>
                </Card>
              ) : (
                audit.all_findings.map((finding, index) => (
                  <Collapsible key={index} open={expandedFindings.has(index)} onOpenChange={() => toggleFinding(index)}>
                    <Card className={`border ${getSeverityColor(finding.severity).split(" ")[2]}`}>
                      <CollapsibleTrigger asChild>
                        <CardHeader className="cursor-pointer hover:bg-accent/50">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start gap-3">
                              {expandedFindings.has(index) ? (
                                <ChevronDown className="mt-1 h-4 w-4" />
                              ) : (
                                <ChevronRight className="mt-1 h-4 w-4" />
                              )}
                              <div className="space-y-1">
                                <CardTitle className="text-base">{finding.issue}</CardTitle>
                                <CardDescription className="flex items-center gap-2">
                                  <Lock className="h-3 w-3" />
                                  {finding.affected_object}
                                </CardDescription>
                              </div>
                            </div>
                            <Badge className={getSeverityColor(finding.severity)}>{finding.severity}</Badge>
                          </div>
                        </CardHeader>
                      </CollapsibleTrigger>
                      <CollapsibleContent>
                        <CardContent className="space-y-4 border-t border-border pt-4">
                          <div>
                            <h4 className="mb-1 text-sm font-medium text-muted-foreground">Description</h4>
                            <p className="text-sm">{finding.description}</p>
                          </div>
                          <div>
                            <h4 className="mb-1 text-sm font-medium text-muted-foreground">Impact</h4>
                            <p className="text-sm text-orange-300">{finding.impact}</p>
                          </div>
                          <div>
                            <h4 className="mb-1 text-sm font-medium text-muted-foreground">Remediation</h4>
                            <div className="rounded-lg bg-muted/50 p-3">
                              <pre className="whitespace-pre-wrap text-sm text-green-300">{finding.remediation}</pre>
                            </div>
                          </div>
                          <div className="rounded-lg bg-muted/30 p-3">
                            <h4 className="mb-2 text-sm font-medium text-muted-foreground">Permission Details</h4>
                            <div className="grid gap-2 text-xs">
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Identity:</span>
                                <span className="font-mono">{finding.details.identity}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Rights:</span>
                                <span className="font-mono text-red-400">
                                  {finding.details.active_directory_rights}
                                </span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Object DN:</span>
                                <span className="font-mono text-xs">{finding.details.object_dn}</span>
                              </div>
                              {finding.details.expected_rights && (
                                <div className="flex justify-between">
                                  <span className="text-muted-foreground">Expected Rights:</span>
                                  <span className="font-mono text-green-400">{finding.details.expected_rights}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        </CardContent>
                      </CollapsibleContent>
                    </Card>
                  </Collapsible>
                ))
              )}
            </TabsContent>

            <TabsContent value="critical-ous" className="space-y-4">
              {audit.critical_ous.map((ou, index) => (
                <Collapsible key={index} open={expandedOus.has(index)} onOpenChange={() => toggleOu(index)}>
                  <Card className="border-border bg-card">
                    <CollapsibleTrigger asChild>
                      <CardHeader className="cursor-pointer hover:bg-accent/50">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            {expandedOus.has(index) ? (
                              <ChevronDown className="h-4 w-4" />
                            ) : (
                              <ChevronRight className="h-4 w-4" />
                            )}
                            <Folder className="h-5 w-5 text-yellow-400" />
                            <div>
                              <CardTitle className="text-base">{ou.ou_name}</CardTitle>
                              <CardDescription className="font-mono text-xs">{ou.ou_dn}</CardDescription>
                            </div>
                          </div>
                          <Badge variant={ou.findings.length > 0 ? "destructive" : "secondary"}>
                            {ou.findings.length} Issue{ou.findings.length !== 1 ? "s" : ""}
                          </Badge>
                        </div>
                      </CardHeader>
                    </CollapsibleTrigger>
                    <CollapsibleContent>
                      <CardContent className="space-y-3 border-t border-border pt-4">
                        {ou.dangerous_permissions.length === 0 ? (
                          <p className="text-sm text-green-400">No dangerous permissions found on this OU.</p>
                        ) : (
                          ou.dangerous_permissions.map((perm, i) => (
                            <div key={i} className="rounded-lg bg-muted/30 p-3">
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                  <Users className="h-4 w-4 text-muted-foreground" />
                                  <span className="font-medium">{perm.identity_reference}</span>
                                </div>
                                <Badge className="bg-red-500/20 text-red-400">{perm.active_directory_rights}</Badge>
                              </div>
                              <div className="mt-2 text-xs text-muted-foreground">
                                <span>SID: {perm.identity_sid}</span>
                                <span className="mx-2">|</span>
                                <span>Inherited: {perm.is_inherited ? "Yes" : "No"}</span>
                              </div>
                            </div>
                          ))
                        )}
                      </CardContent>
                    </CollapsibleContent>
                  </Card>
                </Collapsible>
              ))}
            </TabsContent>

            <TabsContent value="recommendations" className="space-y-4">
              {audit.recommendations.map((rec, index) => (
                <Card key={index} className="border-border bg-card">
                  <CardHeader>
                    <div className="flex items-start gap-3">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-primary-foreground">
                        {rec.priority}
                      </div>
                      <div>
                        <CardTitle className="text-base">{rec.title}</CardTitle>
                        <CardDescription>{rec.description}</CardDescription>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <ol className="space-y-2">
                      {rec.steps.map((step, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm">
                          <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-muted text-xs">
                            {i + 1}
                          </span>
                          <span className="flex-1 text-muted-foreground">{step}</span>
                          {(step.includes("GUID") || step.includes("Event ID")) && (
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-5 w-5 p-0"
                              onClick={() => {
                                const match = step.match(/[0-9a-f-]{36}|Event ID \d+/i)
                                if (match) copyToClipboard(match[0])
                              }}
                            >
                              {copiedText && step.includes(copiedText) ? (
                                <CheckCircle className="h-3 w-3 text-green-400" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                            </Button>
                          )}
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
