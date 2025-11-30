"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
  ShieldAlert,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Copy,
  CheckCircle2,
  Ghost,
  Key,
  History,
  Database,
  Shield,
  Users,
  Lock,
  ExternalLink,
} from "lucide-react"
import { auditDAEquivalence, type DAEquivalenceAudit, type DAEquivalenceFinding } from "@/lib/tauri-api"

interface DAEquivalenceAuditViewProps {
  isConnected: boolean
}

export function DAEquivalenceAuditView({ isConnected }: DAEquivalenceAuditViewProps) {
  const [audit, setAudit] = useState<DAEquivalenceAudit | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set())
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null)

  const runAudit = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const result = await auditDAEquivalence()
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
          <ShieldAlert className="mb-4 h-12 w-12 text-muted-foreground" />
          <h3 className="mb-2 text-lg font-medium text-foreground">Not Connected</h3>
          <p className="text-center text-sm text-muted-foreground">
            Connect to Active Directory to audit Domain Admin equivalence paths
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
          <h2 className="text-2xl font-bold text-foreground">Domain Admin Equivalence Audit</h2>
          <p className="text-sm text-muted-foreground">Detect hidden paths to Domain Admin-level privileges</p>
        </div>
        <Button onClick={runAudit} disabled={isLoading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
          {isLoading ? "Scanning..." : "Run Audit"}
        </Button>
      </div>

      {/* Info Alert */}
      <Alert className="border-primary/30 bg-primary/10">
        <ShieldAlert className="h-4 w-4 text-primary" />
        <AlertTitle className="text-primary">What is Domain Admin Equivalence?</AlertTitle>
        <AlertDescription className="text-primary/80">
          This audit identifies principals with permissions that effectively grant Domain Admin-level control, including
          DCSync rights, AdminSDHolder manipulation, SID History injection, PKI abuse paths, and membership in dangerous
          built-in groups. These are often exploited in real-world attacks.
        </AlertDescription>
      </Alert>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {audit && (
        <>
          {/* Risk Score Overview */}
          <Card className="border-border bg-card">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Overall Risk Score</p>
                  <p className={`text-4xl font-bold ${getRiskScoreColor(audit.risk_score)}`}>{audit.risk_score}/100</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {audit.total_equivalent_principals} principals with DA-equivalent access
                  </p>
                </div>
                <Shield className={`h-16 w-16 ${getRiskScoreColor(audit.risk_score)}`} />
              </div>
            </CardContent>
          </Card>

          {/* Categorized Counters */}
          <div className="space-y-4">
            {/* Credential Theft Category */}
            <Card className="border-border bg-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Credential Theft & Persistence</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                  <MetricCard label="Ghost Accounts" value={audit.ghost_accounts_count} severity="high" />
                  <MetricCard label="Shadow Credentials" value={audit.shadow_credentials_count} severity="critical" />
                  <MetricCard
                    label="Shadow Cred Writes"
                    value={audit.shadow_credential_write_count}
                    severity="high"
                  />
                  <MetricCard label="SID History" value={audit.sid_history_issues} severity="critical" />
                  <MetricCard label="DCSync Rights" value={audit.dcsync_principals} severity="critical" />
                  <MetricCard label="Weak Passwords" value={audit.weak_password_configs} severity="medium" />
                </div>
              </CardContent>
            </Card>

            {/* PKI/ADCS Vulnerabilities Category */}
            <Card className="border-border bg-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">PKI/ADCS Vulnerabilities</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                  <MetricCard label="ESC1" value={audit.esc1_count} severity="critical" badge="Template Misc" />
                  <MetricCard label="ESC2" value={audit.esc2_count} severity="high" badge="Any Purpose" />
                  <MetricCard label="ESC3" value={audit.esc3_count} severity="high" badge="Enroll Agent" />
                  <MetricCard label="ESC4" value={audit.esc4_count} severity="high" badge="Template ACL" />
                  <MetricCard label="ESC5" value={audit.esc5_count} severity="medium" badge="PKI Object ACL" />
                  <MetricCard label="ESC7" value={audit.esc7_count} severity="critical" badge="CA ACL" />
                  <MetricCard label="ESC8" value={audit.esc8_count} severity="high" badge="NTLM Relay" />
                  <MetricCard label="Total PKI" value={audit.pki_vulnerabilities} severity="high" />
                </div>
              </CardContent>
            </Card>

            {/* Permission-Based Attacks Category */}
            <Card className="border-border bg-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Permission-Based Attacks</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                  <MetricCard label="Privileged Takeover" value={audit.privileged_takeover_count} severity="critical" />
                  <MetricCard label="Group Control" value={audit.group_membership_control_count} severity="critical" />
                  <MetricCard label="RBCD Write" value={audit.rbcd_write_count} severity="high" />
                  <MetricCard label="Write SPN" value={audit.write_spn_count} severity="high" />
                  <MetricCard label="Computer Control" value={audit.computer_control_count} severity="high" />
                  <MetricCard label="OU Control" value={audit.ou_control_count} severity="medium" />
                  <MetricCard label="GPO Control" value={audit.gpo_control_count} severity="critical" />
                  <MetricCard label="GPO Link Rights" value={audit.gpo_link_rights_count} severity="high" />
                </div>
              </CardContent>
            </Card>

            {/* Delegation & Modern Threats Category */}
            <Card className="border-border bg-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Delegation & Modern Threats</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                  <MetricCard
                    label="Unconstrained Delegation"
                    value={audit.unconstrained_delegation_count}
                    severity="high"
                  />
                  <MetricCard
                    label="Constrained to DC"
                    value={audit.constrained_delegation_to_dc_count}
                    severity="critical"
                  />
                  <MetricCard label="Azure AD Connect" value={audit.azure_ad_connect_count} severity="critical" />
                  <MetricCard label="Exchange PrivExchange" value={audit.exchange_privexchange_count} severity="high" />
                  <MetricCard label="DNS Zone Control" value={audit.dns_zone_control_count} severity="high" />
                  <MetricCard label="LAPS Exposure" value={audit.laps_exposures} severity="high" />
                  <MetricCard label="GMSA Exposure" value={audit.gmsa_exposures} severity="medium" />
                  <MetricCard label="Legacy Scripts" value={audit.legacy_logon_script_count} severity="low" />
                  <MetricCard label="Dangerous Groups" value={audit.dangerous_group_members} severity="high" />
                  <MetricCard label="Session Groups" value={audit.session_group_count} severity="medium" />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Tabs */}
          <Tabs defaultValue="findings" className="w-full">
            <TabsList className="bg-muted">
              <TabsTrigger value="findings">Findings ({audit.findings.length})</TabsTrigger>
              <TabsTrigger value="details">Detailed Analysis</TabsTrigger>
              <TabsTrigger value="recommendations">Recommendations ({audit.recommendations.length})</TabsTrigger>
            </TabsList>

            <TabsContent value="findings" className="mt-4 space-y-3">
              {audit.findings.length === 0 ? (
                <Card className="border-border bg-card">
                  <CardContent className="flex items-center justify-center py-8">
                    <CheckCircle2 className="mr-2 h-5 w-5 text-green-400" />
                    <span className="text-muted-foreground">No Domain Admin equivalence paths found</span>
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

            <TabsContent value="details" className="mt-4 space-y-4">
              {/* Ghost Accounts */}
              {audit.ghost_accounts.length > 0 && (
                <Card className="border-border bg-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <Ghost className="h-4 w-4 text-yellow-400" />
                      Ghost Accounts (adminCount=1 orphans)
                    </CardTitle>
                    <CardDescription>
                      Users with adminCount=1 but not in any protected group - may retain elevated ACLs
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {audit.ghost_accounts.map((account) => (
                        <div
                          key={account.sam_account_name}
                          className="flex items-center justify-between rounded-md bg-muted p-2 text-sm"
                        >
                          <span className="font-mono">{account.sam_account_name}</span>
                          <Badge variant="outline" className="text-yellow-400">
                            adminCount=1
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Shadow Credentials */}
              {audit.shadow_credentials.length > 0 && (
                <Card className="border-border bg-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <Key className="h-4 w-4 text-orange-400" />
                      Shadow Credentials
                    </CardTitle>
                    <CardDescription>
                      Objects with msDS-KeyCredentialLink - may indicate Whisker/Certipy attack
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {audit.shadow_credentials.map((cred) => (
                        <div
                          key={cred.distinguished_name}
                          className="flex items-center justify-between rounded-md bg-muted p-2 text-sm"
                        >
                          <span className="font-mono">{cred.object_name}</span>
                          <Badge variant="outline" className="text-orange-400">
                            {cred.object_class}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* SID History */}
              {audit.sid_history_entries.length > 0 && (
                <Card className="border-border bg-card border-l-4 border-l-red-500">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <History className="h-4 w-4 text-red-400" />
                      SID History Entries
                    </CardTitle>
                    <CardDescription>Same-domain or privileged RID SIDs indicate potential attack</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {audit.sid_history_entries.map((entry) => (
                        <div key={entry.injected_sid} className="rounded-md bg-muted p-3 text-sm">
                          <div className="flex items-center justify-between">
                            <span className="font-mono font-medium">{entry.sam_account_name}</span>
                            <div className="flex gap-2">
                              {entry.is_same_domain && <Badge variant="destructive">Same Domain SID</Badge>}
                              {entry.is_privileged_rid && <Badge variant="destructive">RID {entry.rid}</Badge>}
                            </div>
                          </div>
                          <p className="mt-1 font-mono text-xs text-muted-foreground">{entry.injected_sid}</p>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Dangerous Group Members */}
              {audit.dangerous_members.length > 0 && (
                <Card className="border-border bg-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <Users className="h-4 w-4 text-orange-400" />
                      Dangerous Built-in Group Members
                    </CardTitle>
                    <CardDescription>
                      Members of groups with privilege escalation paths (DnsAdmins, Backup Operators, etc.)
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {audit.dangerous_members.map((member, index) => (
                        <div key={index} className="rounded-md bg-muted p-3 text-sm">
                          <div className="flex items-center justify-between">
                            <span className="font-mono font-medium">{member.member_sam_account_name}</span>
                            <Badge variant="outline" className="text-orange-400">
                              {member.group_name}
                            </Badge>
                          </div>
                          <p className="mt-1 text-xs text-muted-foreground">{member.attack_path}</p>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Weak Password Configs */}
              {audit.weak_passwords.length > 0 && (
                <Card className="border-border bg-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <Lock className="h-4 w-4 text-yellow-400" />
                      Weak Password Configurations
                    </CardTitle>
                    <CardDescription>Privileged accounts with insecure password settings</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {audit.weak_passwords.map((config, index) => (
                        <div key={index} className="flex items-center justify-between rounded-md bg-muted p-2 text-sm">
                          <span className="font-mono">{config.account}</span>
                          <Badge variant="outline" className="text-yellow-400">
                            {config.issue}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* ESC1 Vulnerabilities */}
              {audit.esc1_vulnerabilities.length > 0 && (
                <Card className="border-border bg-card border-l-4 border-l-red-500">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <ShieldAlert className="h-4 w-4 text-red-400" />
                      ESC1 - Misconfigured Certificate Templates
                    </CardTitle>
                    <CardDescription>Templates allowing SAN specification with dangerous EKU</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {audit.esc1_vulnerabilities.map((esc, index) => (
                        <div key={index} className="rounded-md bg-muted p-3 text-sm">
                          <div className="flex items-center justify-between">
                            <span className="font-mono font-medium">{esc.template_name}</span>
                            <Badge variant="destructive">Critical</Badge>
                          </div>
                          <div className="mt-2 space-y-1 text-xs text-muted-foreground">
                            <p>• Enrollee can supply subject: {esc.enrollee_supplies_subject ? "Yes" : "No"}</p>
                            <p>• Dangerous EKU: {esc.dangerous_eku ? "Yes" : "No"}</p>
                            <p>• Manager approval required: {esc.no_manager_approval ? "No" : "Yes"}</p>
                            <p>• Enroller: {esc.enroller}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* ESC2-8 Vulnerabilities - Similar pattern */}
              {audit.esc2_vulnerabilities.length > 0 && (
                <Card className="border-border bg-card border-l-4 border-l-orange-500">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <ShieldAlert className="h-4 w-4 text-orange-400" />
                      ESC2 - Any Purpose EKU
                    </CardTitle>
                    <CardDescription>Templates with Any Purpose or no EKU restrictions</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {audit.esc2_vulnerabilities.map((esc, index) => (
                        <div key={index} className="rounded-md bg-muted p-3 text-sm">
                          <span className="font-mono font-medium">{esc.template_name}</span>
                          <div className="mt-2 space-y-1 text-xs text-muted-foreground">
                            <p>• Any Purpose EKU: {esc.has_any_purpose_eku ? "Yes" : "No"}</p>
                            <p>• No EKU: {esc.has_no_eku ? "Yes" : "No"}</p>
                            <p>• Enroller: {esc.enroller}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {audit.esc4_vulnerabilities.length > 0 && (
                <Card className="border-border bg-card border-l-4 border-l-orange-500">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <ShieldAlert className="h-4 w-4 text-orange-400" />
                      ESC4 - Template ACL Abuse
                    </CardTitle>
                    <CardDescription>Write access to certificate templates</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {audit.esc4_vulnerabilities.map((esc, index) => (
                        <div key={index} className="rounded-md bg-muted p-3 text-sm">
                          <div className="flex items-center justify-between">
                            <span className="font-mono font-medium">{esc.template_name}</span>
                            <Badge variant="outline" className="text-orange-400">
                              {esc.write_access_type}
                            </Badge>
                          </div>
                          <p className="mt-1 text-xs text-muted-foreground">Principal: {esc.principal}</p>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {audit.esc7_vulnerabilities.length > 0 && (
                <Card className="border-border bg-card border-l-4 border-l-red-500">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <ShieldAlert className="h-4 w-4 text-red-400" />
                      ESC7 - CA Management Rights
                    </CardTitle>
                    <CardDescription>ManageCA or ManageCertificates rights on CA</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {audit.esc7_vulnerabilities.map((esc, index) => (
                        <div key={index} className="rounded-md bg-muted p-3 text-sm">
                          <div className="flex items-center justify-between">
                            <span className="font-mono font-medium">{esc.ca_name}</span>
                            <Badge variant="destructive">Critical</Badge>
                          </div>
                          <div className="mt-2 space-y-1 text-xs text-muted-foreground">
                            <p>• Principal: {esc.principal}</p>
                            <p>• Manage CA: {esc.has_manage_ca ? "Yes" : "No"}</p>
                            <p>• Manage Certificates: {esc.has_manage_certificates ? "Yes" : "No"}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            <TabsContent value="recommendations" className="mt-4 space-y-3">
              {audit.recommendations.map((rec, index) => (
                <Card key={index} className="border-border bg-card">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="bg-primary/10 text-primary">
                          Priority {rec.priority}
                        </Badge>
                        <CardTitle className="text-base">{rec.title}</CardTitle>
                      </div>
                      {rec.reference && (
                        <Button variant="ghost" size="sm" asChild>
                          <a href={rec.reference} target="_blank" rel="noopener noreferrer">
                            <ExternalLink className="h-4 w-4" />
                          </a>
                        </Button>
                      )}
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

function RemediationSteps({
  text,
  onCopy,
  copiedId,
  index,
}: {
  text: string
  onCopy: (text: string, id: string) => void
  copiedId: string | null
  index: number
}) {
  // Parse text into code blocks and regular text
  const parseRemediation = (remediation: string) => {
    const blocks: Array<{ type: "text" | "code"; content: string; id: string }> = []
    let blockId = 0

    // Split by common PowerShell command patterns or explicit code block markers
    // Look for lines starting with PS commands or wrapped in backticks
    const lines = remediation.split("\n")
    let currentBlock: { type: "text" | "code"; lines: string[] } = { type: "text", lines: [] }

    lines.forEach((line) => {
      const isPowerShellCommand =
        line.trim().startsWith("Remove-") ||
        line.trim().startsWith("Set-") ||
        line.trim().startsWith("Get-") ||
        line.trim().startsWith("New-") ||
        line.trim().startsWith("Add-") ||
        line.trim().startsWith("Import-") ||
        line.trim().startsWith("Enable-") ||
        line.trim().startsWith("Disable-") ||
        line.trim().startsWith("$") ||
        line.trim().startsWith("```")

      if (isPowerShellCommand && currentBlock.type !== "code") {
        // Save current text block if it has content
        if (currentBlock.lines.length > 0) {
          blocks.push({
            type: currentBlock.type,
            content: currentBlock.lines.join("\n").trim(),
            id: `block-${blockId++}`,
          })
        }
        currentBlock = { type: "code", lines: [line.replace(/```/g, "")] }
      } else if (!isPowerShellCommand && currentBlock.type === "code" && !line.trim()) {
        // Empty line after code block - end code block
        blocks.push({
          type: currentBlock.type,
          content: currentBlock.lines.join("\n").trim(),
          id: `block-${blockId++}`,
        })
        currentBlock = { type: "text", lines: [] }
      } else {
        currentBlock.lines.push(line.replace(/```/g, ""))
      }
    })

    // Add final block
    if (currentBlock.lines.length > 0) {
      blocks.push({
        type: currentBlock.type,
        content: currentBlock.lines.join("\n").trim(),
        id: `block-${blockId++}`,
      })
    }

    return blocks
  }

  const blocks = parseRemediation(text)

  return (
    <div className="space-y-3">
      {blocks.map((block, blockIndex) =>
        block.type === "code" ? (
          <div key={block.id} className="relative">
            <pre className="overflow-x-auto rounded-md border border-primary/20 bg-slate-950 p-3 text-xs text-green-400">
              {block.content}
            </pre>
            <Button
              variant="ghost"
              size="sm"
              className="absolute right-2 top-2 h-7 w-7 bg-slate-900/80 hover:bg-slate-800"
              onClick={() => onCopy(block.content, `finding-${index}-${block.id}`)}
            >
              {copiedId === `finding-${index}-${block.id}` ? (
                <CheckCircle2 className="h-3 w-3 text-green-400" />
              ) : (
                <Copy className="h-3 w-3 text-muted-foreground" />
              )}
            </Button>
          </div>
        ) : (
          <p key={block.id} className="text-sm text-muted-foreground">
            {block.content}
          </p>
        )
      )}
      {blocks.length === 0 && (
        <div className="relative">
          <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs text-muted-foreground">{text}</pre>
          <Button
            variant="ghost"
            size="sm"
            className="absolute right-2 top-2"
            onClick={() => onCopy(text, `finding-${index}`)}
          >
            {copiedId === `finding-${index}` ? (
              <CheckCircle2 className="h-4 w-4 text-green-400" />
            ) : (
              <Copy className="h-4 w-4" />
            )}
          </Button>
        </div>
      )}
    </div>
  )
}

function MetricCard({
  label,
  value,
  severity,
  badge,
}: {
  label: string
  value: number
  severity: "critical" | "high" | "medium" | "low"
  badge?: string
}) {
  const getSeverityTextColor = () => {
    switch (severity) {
      case "critical":
        return "text-red-400"
      case "high":
        return "text-orange-400"
      case "medium":
        return "text-yellow-400"
      case "low":
        return "text-blue-400"
    }
  }

  const getSeverityBgColor = () => {
    switch (severity) {
      case "critical":
        return "bg-red-500/10 border-red-500/30"
      case "high":
        return "bg-orange-500/10 border-orange-500/30"
      case "medium":
        return "bg-yellow-500/10 border-yellow-500/30"
      case "low":
        return "bg-blue-500/10 border-blue-500/30"
    }
  }

  return (
    <div
      className={`flex flex-col justify-between rounded-md border p-3 ${value > 0 ? getSeverityBgColor() : "border-border bg-card/50"}`}
    >
      <div className="flex items-start justify-between">
        <p className="text-xs text-muted-foreground">{label}</p>
        {badge && value > 0 && (
          <Badge variant="outline" className="text-[10px]">
            {badge}
          </Badge>
        )}
      </div>
      <p className={`mt-1 text-xl font-bold ${value > 0 ? getSeverityTextColor() : "text-muted-foreground"}`}>
        {value}
      </p>
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
  finding: DAEquivalenceFinding
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
            {finding.evidence.length > 0 && (
              <div>
                <h4 className="mb-1 text-sm font-medium text-foreground">Evidence</h4>
                <div className="space-y-2">
                  {finding.evidence.map((ev, evIndex) => (
                    <div key={evIndex} className="rounded-md bg-muted p-2 text-xs">
                      <p className="text-muted-foreground">{ev.reason}</p>
                      {ev.attack_path && <p className="mt-1 text-red-400">Attack Path: {ev.attack_path}</p>}
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div>
              <h4 className="mb-1 text-sm font-medium text-foreground">Remediation</h4>
              <RemediationSteps text={finding.remediation} onCopy={onCopy} copiedId={copiedCommand} index={index} />
            </div>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  )
}
