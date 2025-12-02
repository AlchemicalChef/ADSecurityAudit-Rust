/**
 * Kerberos Delegation Audit Component
 *
 * Analyzes Kerberos delegation configurations across the domain to identify
 * potential privilege escalation vectors and lateral movement opportunities.
 *
 * @module components/delegation-audit
 *
 * Delegation Types Analyzed:
 * - Unconstrained Delegation (CRITICAL) - Can impersonate any user to any service
 * - Constrained Delegation (HIGH) - Can impersonate users to specific services
 * - Constrained with Protocol Transition / T2A4D (CRITICAL) - No credential required
 * - Resource-Based Constrained Delegation / RBCD (MEDIUM) - Target controls delegation
 *
 * Security Impact:
 * - Unconstrained delegation collects TGTs in memory (Printer Bug, PrivExchange)
 * - Constrained delegation can be exploited for lateral movement
 * - Protocol transition allows impersonation without user credentials
 * - RBCD can be abused if attacker modifies msDS-AllowedToActOnBehalfOfOtherIdentity
 *
 * Recommendations Generated:
 * - Migration to Group Managed Service Accounts (gMSA)
 * - Conversion from unconstrained to constrained delegation
 * - Implementation of RBCD where appropriate
 * - Enabling "Account is sensitive" flag for admins
 *
 * @see https://attack.mitre.org/techniques/T1558/ - Kerberos delegation attacks
 */
"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
  Shield,
  AlertTriangle,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  User,
  Monitor,
  Key,
  CheckCircle,
  Copy,
} from "lucide-react"
import { auditDelegation, type DelegationAudit } from "@/lib/tauri-api"
import { useToggleSet } from "@/hooks/use-toggle-set"
import { useClipboard } from "@/hooks/use-clipboard"
import { getSeverityColor, getRiskLevel } from "@/lib/severity-utils"

interface DelegationAuditViewProps {
  isConnected: boolean
}

export function DelegationAuditView({ isConnected }: DelegationAuditViewProps) {
  const [audit, setAudit] = useState<DelegationAudit | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { toggle: toggleFinding, has: isExpanded } = useToggleSet<number>()
  const { copyToClipboard, isCopied } = useClipboard<number>()

  const runAudit = async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await auditDelegation()
      setAudit(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run delegation audit")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (isConnected) {
      runAudit()
    }
  }, [isConnected])

  const getDelegationTypeIcon = (type: string) => {
    switch (type) {
      case "Unconstrained":
        return <AlertTriangle className="h-4 w-4 text-red-400" />
      case "ConstrainedWithProtocolTransition":
        return <Key className="h-4 w-4 text-orange-400" />
      case "Constrained":
        return <Shield className="h-4 w-4 text-yellow-400" />
      case "ResourceBased":
        return <Monitor className="h-4 w-4 text-blue-400" />
      default:
        return <Shield className="h-4 w-4" />
    }
  }

  const getAccountTypeIcon = (type: string) => {
    switch (type) {
      case "User":
        return <User className="h-4 w-4" />
      case "Computer":
        return <Monitor className="h-4 w-4" />
      default:
        return <Key className="h-4 w-4" />
    }
  }

  if (!isConnected) {
    return (
      <div className="flex h-full items-center justify-center">
        <Card className="max-w-md">
          <CardHeader className="text-center">
            <Shield className="mx-auto h-12 w-12 text-muted-foreground" />
            <CardTitle>Connection Required</CardTitle>
            <CardDescription>Connect to Active Directory to audit Kerberos delegation configurations.</CardDescription>
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
          <h2 className="text-2xl font-bold text-foreground">Delegation Audit</h2>
          <p className="text-muted-foreground">Analyze Kerberos delegation configurations for security risks</p>
        </div>
        <Button onClick={runAudit} disabled={loading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          {loading ? "Scanning..." : "Run Audit"}
        </Button>
      </div>

      {/* Educational Alert */}
      <Alert className="border-blue-500/50 bg-blue-500/10">
        <Shield className="h-4 w-4 text-blue-400" />
        <AlertTitle className="text-blue-400">About Kerberos Delegation</AlertTitle>
        <AlertDescription className="text-blue-300/80">
          Kerberos delegation allows services to impersonate users when accessing other resources.
          <strong> Unconstrained delegation</strong> is most dangerous (can impersonate to any service).
          <strong> Protocol Transition (T2A4D)</strong> allows impersonation without user interaction.
          <strong> RBCD</strong> is more secure but still needs auditing.
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
                <CardDescription>Total Delegations</CardDescription>
                <CardTitle className="text-3xl">{audit.total_delegations}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-red-500/30 bg-red-500/10">
              <CardHeader className="pb-2">
                <CardDescription className="text-red-400">Unconstrained</CardDescription>
                <CardTitle className="text-3xl text-red-400">{audit.unconstrained_count}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-orange-500/30 bg-orange-500/10">
              <CardHeader className="pb-2">
                <CardDescription className="text-orange-400">Protocol Transition</CardDescription>
                <CardTitle className="text-3xl text-orange-400">{audit.protocol_transition_count}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-yellow-500/30 bg-yellow-500/10">
              <CardHeader className="pb-2">
                <CardDescription className="text-yellow-400">Constrained</CardDescription>
                <CardTitle className="text-3xl text-yellow-400">{audit.constrained_count}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-blue-500/30 bg-blue-500/10">
              <CardHeader className="pb-2">
                <CardDescription className="text-blue-400">RBCD</CardDescription>
                <CardTitle className="text-3xl text-blue-400">{audit.rbcd_count}</CardTitle>
              </CardHeader>
            </Card>
          </div>

          {/* Risk Score */}
          <Card className="border-border bg-card">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Overall Risk Assessment</CardTitle>
                  <CardDescription>Based on delegation configurations found</CardDescription>
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
              <TabsTrigger value="findings">Findings ({audit.findings.length})</TabsTrigger>
              <TabsTrigger value="delegations">All Delegations ({audit.delegations.length})</TabsTrigger>
              <TabsTrigger value="recommendations">Recommendations ({audit.recommendations.length})</TabsTrigger>
            </TabsList>

            <TabsContent value="findings" className="space-y-4">
              {audit.findings.length === 0 ? (
                <Card className="border-green-500/30 bg-green-500/10">
                  <CardContent className="flex items-center gap-3 py-6">
                    <CheckCircle className="h-6 w-6 text-green-400" />
                    <p className="text-green-400">No critical delegation issues found.</p>
                  </CardContent>
                </Card>
              ) : (
                audit.findings.map((finding, index) => (
                  <Collapsible key={index} open={isExpanded(index)} onOpenChange={() => toggleFinding(index)}>
                    <Card className={`border ${getSeverityColor(finding.severity).split(" ")[2]}`}>
                      <CollapsibleTrigger asChild>
                        <CardHeader className="cursor-pointer hover:bg-accent/50">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start gap-3">
                              {isExpanded(index) ? (
                                <ChevronDown className="mt-1 h-4 w-4" />
                              ) : (
                                <ChevronRight className="mt-1 h-4 w-4" />
                              )}
                              <div className="space-y-1">
                                <div className="flex items-center gap-2">
                                  {getDelegationTypeIcon(finding.delegation_type)}
                                  <CardTitle className="text-base">{finding.issue}</CardTitle>
                                </div>
                                <CardDescription className="flex items-center gap-2">
                                  {getAccountTypeIcon(finding.account_type)}
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
                            <p className="text-sm text-green-300">{finding.remediation}</p>
                          </div>
                          {finding.details.allowed_to_delegate_to.length > 0 && (
                            <div>
                              <h4 className="mb-1 text-sm font-medium text-muted-foreground">Allowed to Delegate To</h4>
                              <div className="flex flex-wrap gap-2">
                                {finding.details.allowed_to_delegate_to.map((spn, i) => (
                                  <Badge key={i} variant="outline" className="font-mono text-xs">
                                    {spn}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                        </CardContent>
                      </CollapsibleContent>
                    </Card>
                  </Collapsible>
                ))
              )}
            </TabsContent>

            <TabsContent value="delegations" className="space-y-4">
              {audit.delegations.map((delegation, index) => (
                <Card key={index} className="border-border bg-card">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {getAccountTypeIcon(delegation.account_type)}
                        <div>
                          <CardTitle className="text-base">{delegation.sam_account_name}</CardTitle>
                          <CardDescription className="font-mono text-xs">
                            {delegation.distinguished_name}
                          </CardDescription>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {delegation.enabled ? (
                          <Badge className="bg-green-500/20 text-green-400">Enabled</Badge>
                        ) : (
                          <Badge className="bg-muted text-muted-foreground">Disabled</Badge>
                        )}
                        <Badge variant="outline">{delegation.delegation_type}</Badge>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {delegation.allowed_to_delegate_to.length > 0 && (
                      <div>
                        <span className="text-xs text-muted-foreground">Allowed to delegate to:</span>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {delegation.allowed_to_delegate_to.map((spn, i) => (
                            <Badge key={i} variant="secondary" className="font-mono text-xs">
                              {spn}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="flex gap-4 text-xs text-muted-foreground">
                      <span>T2A4D: {delegation.trusted_to_auth_for_delegation ? "Yes" : "No"}</span>
                      <span>Unconstrained: {delegation.trusted_for_delegation ? "Yes" : "No"}</span>
                    </div>
                  </CardContent>
                </Card>
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
                          <span className="text-muted-foreground">{step}</span>
                          {step.includes(":") && step.includes("-") && (
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-5 w-5 p-0"
                              onClick={() => copyToClipboard(step.split(": ")[1] || step, i)}
                            >
                              {isCopied(i) ? (
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
