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
  ArrowLeftRight,
  ArrowLeft,
  ArrowRight,
  Network,
  CheckCircle,
  Copy,
  ExternalLink,
} from "lucide-react"
import { auditDomainTrusts, type DomainTrustAudit } from "@/lib/tauri-api"

interface DomainTrustAuditViewProps {
  isConnected: boolean
}

export function DomainTrustAuditView({ isConnected }: DomainTrustAuditViewProps) {
  const [audit, setAudit] = useState<DomainTrustAudit | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set())
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null)

  const runAudit = async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await auditDomainTrusts()
      setAudit(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run domain trust audit")
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

  const copyToClipboard = async (text: string) => {
    await navigator.clipboard.writeText(text)
    setCopiedCommand(text)
    setTimeout(() => setCopiedCommand(null), 2000)
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

  const getDirectionIcon = (direction: string) => {
    switch (direction) {
      case "Bidirectional":
        return <ArrowLeftRight className="h-4 w-4 text-yellow-400" />
      case "Inbound":
        return <ArrowLeft className="h-4 w-4 text-blue-400" />
      case "Outbound":
        return <ArrowRight className="h-4 w-4 text-green-400" />
      default:
        return <Network className="h-4 w-4" />
    }
  }

  const getTrustTypeColor = (type: string) => {
    switch (type) {
      case "Forest":
        return "bg-purple-500/20 text-purple-400"
      case "External":
        return "bg-blue-500/20 text-blue-400"
      case "ParentChild":
        return "bg-green-500/20 text-green-400"
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  if (!isConnected) {
    return (
      <div className="flex h-full items-center justify-center">
        <Card className="max-w-md">
          <CardHeader className="text-center">
            <Network className="mx-auto h-12 w-12 text-muted-foreground" />
            <CardTitle>Connection Required</CardTitle>
            <CardDescription>Connect to Active Directory to audit domain trust relationships.</CardDescription>
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
          <h2 className="text-2xl font-bold text-foreground">Domain Trust Audit</h2>
          <p className="text-muted-foreground">Analyze domain trust relationships for security vulnerabilities</p>
        </div>
        <Button onClick={runAudit} disabled={loading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          {loading ? "Scanning..." : "Run Audit"}
        </Button>
      </div>

      {/* Educational Alert */}
      <Alert className="border-purple-500/50 bg-purple-500/10">
        <Network className="h-4 w-4 text-purple-400" />
        <AlertTitle className="text-purple-400">About Domain Trusts</AlertTitle>
        <AlertDescription className="text-purple-300/80">
          Domain trusts allow authentication between domains. Key security concerns include:
          <strong> SID Filtering</strong> (prevents SID history attacks on external trusts),
          <strong> Selective Authentication</strong> (limits which users can authenticate across forest trusts), and
          <strong> Bidirectional trusts</strong> (increase attack surface).
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
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card className="border-border bg-card">
              <CardHeader className="pb-2">
                <CardDescription>Total Trusts</CardDescription>
                <CardTitle className="text-3xl">{audit.total_trusts}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-red-500/30 bg-red-500/10">
              <CardHeader className="pb-2">
                <CardDescription className="text-red-400">No SID Filtering</CardDescription>
                <CardTitle className="text-3xl text-red-400">{audit.trusts_without_sid_filtering}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-orange-500/30 bg-orange-500/10">
              <CardHeader className="pb-2">
                <CardDescription className="text-orange-400">No Selective Auth</CardDescription>
                <CardTitle className="text-3xl text-orange-400">{audit.trusts_without_selective_auth}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-yellow-500/30 bg-yellow-500/10">
              <CardHeader className="pb-2">
                <CardDescription className="text-yellow-400">Bidirectional</CardDescription>
                <CardTitle className="text-3xl text-yellow-400">{audit.bidirectional_trusts}</CardTitle>
              </CardHeader>
            </Card>
          </div>

          {/* Trust Overview */}
          <div className="grid gap-4 md:grid-cols-3">
            <Card className="border-border bg-card">
              <CardHeader className="pb-2">
                <div className="flex items-center gap-2">
                  <ArrowLeft className="h-4 w-4 text-blue-400" />
                  <CardDescription>Inbound Trusts</CardDescription>
                </div>
                <CardTitle className="text-2xl">{audit.inbound_trusts}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-border bg-card">
              <CardHeader className="pb-2">
                <div className="flex items-center gap-2">
                  <ArrowRight className="h-4 w-4 text-green-400" />
                  <CardDescription>Outbound Trusts</CardDescription>
                </div>
                <CardTitle className="text-2xl">{audit.outbound_trusts}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-border bg-card">
              <CardHeader className="pb-2">
                <div className="flex items-center gap-2">
                  <ExternalLink className="h-4 w-4 text-purple-400" />
                  <CardDescription>Forest Trusts</CardDescription>
                </div>
                <CardTitle className="text-2xl">{audit.forest_trusts}</CardTitle>
              </CardHeader>
            </Card>
          </div>

          {/* Tabs */}
          <Tabs defaultValue="findings" className="space-y-4">
            <TabsList>
              <TabsTrigger value="findings">Findings ({audit.findings.length})</TabsTrigger>
              <TabsTrigger value="trusts">All Trusts ({audit.trusts.length})</TabsTrigger>
              <TabsTrigger value="recommendations">Recommendations ({audit.recommendations.length})</TabsTrigger>
            </TabsList>

            <TabsContent value="findings" className="space-y-4">
              {audit.findings.length === 0 ? (
                <Card className="border-green-500/30 bg-green-500/10">
                  <CardContent className="flex items-center gap-3 py-6">
                    <CheckCircle className="h-6 w-6 text-green-400" />
                    <p className="text-green-400">No domain trust security issues found.</p>
                  </CardContent>
                </Card>
              ) : (
                audit.findings.map((finding, index) => (
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
                                  <Network className="h-3 w-3" />
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
                            <div className="flex items-start justify-between gap-2 rounded-lg bg-muted/50 p-3">
                              <code className="text-sm text-green-300">{finding.remediation}</code>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="shrink-0"
                                onClick={() => copyToClipboard(finding.remediation)}
                              >
                                {copiedCommand === finding.remediation ? (
                                  <CheckCircle className="h-4 w-4 text-green-400" />
                                ) : (
                                  <Copy className="h-4 w-4" />
                                )}
                              </Button>
                            </div>
                          </div>
                          {finding.details && (
                            <div className="rounded-lg bg-muted/30 p-3">
                              <h4 className="mb-2 text-sm font-medium text-muted-foreground">Details</h4>
                              <div className="grid gap-2 text-xs">
                                <div className="flex justify-between">
                                  <span className="text-muted-foreground">Target Domain:</span>
                                  <span>{finding.details.target}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-muted-foreground">Direction:</span>
                                  <span>{finding.details.direction}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-muted-foreground">Trust Type:</span>
                                  <span>{finding.details.trust_type}</span>
                                </div>
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

            <TabsContent value="trusts" className="space-y-4">
              {audit.trusts.length === 0 ? (
                <Card className="border-border bg-card">
                  <CardContent className="flex items-center justify-center py-8">
                    <p className="text-muted-foreground">No domain trusts configured.</p>
                  </CardContent>
                </Card>
              ) : (
                audit.trusts.map((trust, index) => (
                  <Card key={index} className="border-border bg-card">
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          {getDirectionIcon(trust.direction)}
                          <div>
                            <CardTitle className="text-base">{trust.target_domain}</CardTitle>
                            <CardDescription>
                              {trust.direction} trust from {trust.source_domain}
                            </CardDescription>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge className={getTrustTypeColor(trust.trust_type)}>{trust.trust_type}</Badge>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="grid gap-4 md:grid-cols-4">
                        <div className="flex items-center gap-2">
                          {trust.sid_filtering_enabled ? (
                            <CheckCircle className="h-4 w-4 text-green-400" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-red-400" />
                          )}
                          <span className="text-sm">
                            SID Filtering: {trust.sid_filtering_enabled ? "Enabled" : "Disabled"}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          {trust.selective_authentication ? (
                            <CheckCircle className="h-4 w-4 text-green-400" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-orange-400" />
                          )}
                          <span className="text-sm">
                            Selective Auth: {trust.selective_authentication ? "Enabled" : "Disabled"}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Network className="h-4 w-4 text-muted-foreground" />
                          <span className="text-sm">Transitive: {trust.is_transitive ? "Yes" : "No"}</span>
                        </div>
                        <div className="text-right text-xs text-muted-foreground">
                          Modified: {new Date(trust.modified).toLocaleDateString()}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))
              )}
            </TabsContent>

            <TabsContent value="recommendations" className="space-y-4">
              {audit.recommendations.map((rec, index) => (
                <Card key={index} className="border-border bg-card">
                  <CardHeader>
                    <div className="flex items-start gap-3">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-primary-foreground">
                        {rec.priority}
                      </div>
                      <div className="flex-1">
                        <CardTitle className="text-base">{rec.title}</CardTitle>
                        <CardDescription>{rec.description}</CardDescription>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center justify-between rounded-lg bg-muted/50 p-3">
                      <code className="text-sm text-primary">{rec.command}</code>
                      <Button size="sm" variant="ghost" onClick={() => copyToClipboard(rec.command)}>
                        {copiedCommand === rec.command ? (
                          <CheckCircle className="h-4 w-4 text-green-400" />
                        ) : (
                          <Copy className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                    <ol className="space-y-2">
                      {rec.steps.map((step, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm">
                          <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-muted text-xs">
                            {i + 1}
                          </span>
                          <span className="text-muted-foreground">{step}</span>
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
