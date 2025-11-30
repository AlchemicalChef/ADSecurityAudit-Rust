"use client"

import { useState, useEffect } from "react"
import { invoke } from "@tauri-apps/api/core"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { AlertCircle, Download, Filter, RefreshCw, FileText, BarChart3 } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import type {
  AuditEntry,
  AuditCategory,
  AuditSeverity,
  ComplianceStandard,
  AuditStatistics,
  ComplianceReport,
} from "@/lib/advanced-features-types"
import { format } from "date-fns"

interface AuditLogViewerProps {
  isConnected: boolean
}

export function AuditLogViewer({ isConnected }: AuditLogViewerProps) {
  const [logs, setLogs] = useState<AuditEntry[]>([])
  const [statistics, setStatistics] = useState<AuditStatistics | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [categoryFilter, setCategoryFilter] = useState<AuditCategory | "all">("all")
  const [severityFilter, setSeverityFilter] = useState<AuditSeverity | "all">("all")
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")
  const [actorFilter, setActorFilter] = useState("")

  // Compliance
  const [complianceStandard, setComplianceStandard] = useState<ComplianceStandard>("SOC2")
  const [complianceReport, setComplianceReport] = useState<ComplianceReport | null>(null)

  const categories: (AuditCategory | "all")[] = [
    "all",
    "authentication",
    "authorization",
    "user_management",
    "group_management",
    "privilege_escalation",
    "configuration_change",
    "data_access",
    "security_analysis",
    "incident_response",
    "compliance",
    "system_event",
  ]

  const severities: (AuditSeverity | "all")[] = ["all", "info", "warning", "error", "critical"]

  const standards: ComplianceStandard[] = ["SOC2", "HIPAA", "PCI_DSS", "GDPR", "ISO27001"]

  const fetchLogs = async () => {
    if (!isConnected) {
      setError("Not connected to Active Directory")
      return
    }

    setLoading(true)
    setError(null)

    try {
      const params: any = {}
      if (startDate) params.startTime = new Date(startDate).toISOString()
      if (endDate) params.endTime = new Date(endDate).toISOString()
      if (categoryFilter !== "all") params.category = categoryFilter
      if (severityFilter !== "all") params.severity = severityFilter

      const result = await invoke<AuditEntry[]>("query_audit_logs", params)
      setLogs(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  const fetchStatistics = async () => {
    if (!isConnected) return

    try {
      const params: any = {}
      if (startDate) params.startTime = new Date(startDate).toISOString()
      if (endDate) params.endTime = new Date(endDate).toISOString()

      const result = await invoke<AuditStatistics>("get_audit_statistics", params)
      setStatistics(result)
    } catch (err) {
      console.error("Failed to fetch statistics:", err)
    }
  }

  const generateComplianceReport = async () => {
    if (!isConnected) return

    setLoading(true)
    try {
      const result = await invoke<ComplianceReport>("generate_compliance_report", {
        standard: complianceStandard,
        startTime: startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        endTime: endDate || new Date().toISOString(),
      })
      setComplianceReport(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (isConnected) {
      fetchLogs()
      fetchStatistics()
    }
  }, [isConnected])

  const getSeverityColor = (severity: AuditSeverity) => {
    switch (severity) {
      case "critical":
        return "bg-red-500 text-white"
      case "error":
        return "bg-orange-500 text-white"
      case "warning":
        return "bg-yellow-500 text-black"
      case "info":
        return "bg-blue-500 text-white"
      default:
        return "bg-gray-500 text-white"
    }
  }

  const getCategoryIcon = (category: AuditCategory) => {
    // Return category formatted for display
    return category.replace(/_/g, " ").toUpperCase()
  }

  const exportToCSV = () => {
    const csv = [
      ["Timestamp", "Category", "Severity", "Action", "Actor", "Target", "Result"],
      ...logs.map((log) => [
        log.timestamp,
        log.category,
        log.severity,
        log.action,
        log.actor,
        log.target || "",
        log.result,
      ]),
    ]
      .map((row) => row.join(","))
      .join("\n")

    const blob = new Blob([csv], { type: "text/csv" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `audit-logs-${new Date().toISOString()}.csv`
    a.click()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Audit Logs</h2>
          <p className="text-muted-foreground">Comprehensive security audit trail and compliance reporting</p>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Tabs defaultValue="logs" className="space-y-4">
        <TabsList>
          <TabsTrigger value="logs">
            <FileText className="mr-2 h-4 w-4" />
            Audit Logs
          </TabsTrigger>
          <TabsTrigger value="statistics">
            <BarChart3 className="mr-2 h-4 w-4" />
            Statistics
          </TabsTrigger>
          <TabsTrigger value="compliance">
            <FileText className="mr-2 h-4 w-4" />
            Compliance Reports
          </TabsTrigger>
        </TabsList>

        {/* Audit Logs Tab */}
        <TabsContent value="logs" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Filters</CardTitle>
              <CardDescription>Filter audit logs by category, severity, date range, and actor</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Category</label>
                  <Select value={categoryFilter} onValueChange={(v) => setCategoryFilter(v as AuditCategory | "all")}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {categories.map((cat) => (
                        <SelectItem key={cat} value={cat}>
                          {cat === "all" ? "All Categories" : getCategoryIcon(cat as AuditCategory)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Severity</label>
                  <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v as AuditSeverity | "all")}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {severities.map((sev) => (
                        <SelectItem key={sev} value={sev}>
                          {sev === "all" ? "All Severities" : sev.toUpperCase()}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Start Date</label>
                  <Input type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} />
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">End Date</label>
                  <Input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} />
                </div>
              </div>

              <div className="flex gap-2 mt-4">
                <Button onClick={fetchLogs} disabled={loading || !isConnected}>
                  <Filter className="mr-2 h-4 w-4" />
                  Apply Filters
                </Button>
                <Button variant="outline" onClick={exportToCSV} disabled={logs.length === 0}>
                  <Download className="mr-2 h-4 w-4" />
                  Export CSV
                </Button>
                <Button variant="outline" onClick={fetchStatistics} disabled={!isConnected}>
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Refresh
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Audit Log Entries ({logs.length})</CardTitle>
              <CardDescription>Recent security events and actions</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-2">
                  {loading && <div className="text-center py-8 text-muted-foreground">Loading audit logs...</div>}
                  {!loading && logs.length === 0 && (
                    <div className="text-center py-8 text-muted-foreground">No audit logs found</div>
                  )}
                  {logs.map((log) => (
                    <div key={log.id} className="border rounded-lg p-4 hover:bg-accent/50 transition-colors">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 space-y-1">
                          <div className="flex items-center gap-2">
                            <Badge className={getSeverityColor(log.severity)}>{log.severity.toUpperCase()}</Badge>
                            <Badge variant="outline">{getCategoryIcon(log.category)}</Badge>
                            <span className="text-xs text-muted-foreground">
                              {format(new Date(log.timestamp), "PPpp")}
                            </span>
                          </div>
                          <div className="font-medium">{log.action}</div>
                          <div className="text-sm text-muted-foreground">
                            <span className="font-semibold">Actor:</span> {log.actor}
                            {log.target && (
                              <>
                                {" → "}
                                <span className="font-semibold">Target:</span> {log.target}
                              </>
                            )}
                          </div>
                          <div className="text-sm">
                            <span className="font-semibold">Result:</span> {log.result}
                          </div>
                          {log.domain_name && (
                            <div className="text-xs text-muted-foreground">Domain: {log.domain_name}</div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Statistics Tab */}
        <TabsContent value="statistics" className="space-y-4">
          {statistics && (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Total Events</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{statistics.total_events.toLocaleString()}</div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Unique Actors</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{statistics.unique_actors}</div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Domains</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{statistics.domains_involved}</div>
                </CardContent>
              </Card>
            </div>
          )}

          {statistics && (
            <div className="grid gap-4 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Events by Severity</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {statistics.events_by_severity && Object.entries(statistics.events_by_severity).map(([severity, count]) => (
                      <div key={severity} className="flex items-center justify-between">
                        <Badge className={getSeverityColor(severity as AuditSeverity)}>
                          {severity.toUpperCase()}
                        </Badge>
                        <span className="font-bold">{(count as number).toLocaleString()}</span>
                      </div>
                    ))}
                    {!statistics.events_by_severity && (
                      <div className="text-muted-foreground text-sm">No severity data available</div>
                    )}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Events by Category</CardTitle>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[300px]">
                    <div className="space-y-2">
                      {statistics.events_by_category && Object.entries(statistics.events_by_category).map(([category, count]) => (
                        <div key={category} className="flex items-center justify-between">
                          <span className="text-sm">{getCategoryIcon(category as AuditCategory)}</span>
                          <span className="font-bold">{(count as number).toLocaleString()}</span>
                        </div>
                      ))}
                      {!statistics.events_by_category && (
                        <div className="text-muted-foreground text-sm">No category data available</div>
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* Compliance Reports Tab */}
        <TabsContent value="compliance" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Generate Compliance Report</CardTitle>
              <CardDescription>Create reports for various compliance standards</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Standard</label>
                  <Select value={complianceStandard} onValueChange={(v) => setComplianceStandard(v as ComplianceStandard)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {standards.map((std) => (
                        <SelectItem key={std} value={std}>
                          {std}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Start Date</label>
                  <Input type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} />
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">End Date</label>
                  <Input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} />
                </div>
              </div>

              <Button onClick={generateComplianceReport} disabled={loading || !isConnected} className="mt-4">
                <FileText className="mr-2 h-4 w-4" />
                Generate Report
              </Button>
            </CardContent>
          </Card>

          {complianceReport && (
            <Card>
              <CardHeader>
                <CardTitle>
                  {complianceReport.standard} Compliance Report
                </CardTitle>
                <CardDescription>
                  {format(new Date(complianceReport.start_time), "PP")} -{" "}
                  {format(new Date(complianceReport.end_time), "PP")}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="border rounded-lg p-4">
                    <div className="text-sm text-muted-foreground">Total Events</div>
                    <div className="text-2xl font-bold">{complianceReport.total_events}</div>
                  </div>
                  <div className="border rounded-lg p-4">
                    <div className="text-sm text-muted-foreground">Critical Findings</div>
                    <div className="text-2xl font-bold text-red-500">{complianceReport.critical_findings}</div>
                  </div>
                  <div className="border rounded-lg p-4">
                    <div className="text-sm text-muted-foreground">High Findings</div>
                    <div className="text-2xl font-bold text-orange-500">{complianceReport.high_findings}</div>
                  </div>
                  <div className="border rounded-lg p-4">
                    <div className="text-sm text-muted-foreground">Medium Findings</div>
                    <div className="text-2xl font-bold text-yellow-500">{complianceReport.medium_findings}</div>
                  </div>
                </div>

                <div>
                  <h3 className="font-semibold mb-2">Recommendations</h3>
                  <ul className="list-disc list-inside space-y-1">
                    {complianceReport.recommendations?.map((rec, i) => (
                      <li key={i} className="text-sm">
                        {rec}
                      </li>
                    )) || <li className="text-sm text-muted-foreground">No recommendations</li>}
                  </ul>
                </div>

                <div>
                  <h3 className="font-semibold mb-2">Key Findings ({complianceReport.findings?.length || 0})</h3>
                  <ScrollArea className="h-[300px]">
                    <div className="space-y-2">
                      {complianceReport.findings?.map((finding) => (
                        <div key={finding.id} className="border rounded p-3 text-sm">
                          <div className="flex items-center gap-2 mb-1">
                            <Badge className={getSeverityColor(finding.severity)}>
                              {finding.severity.toUpperCase()}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              {format(new Date(finding.timestamp), "PPpp")}
                            </span>
                          </div>
                          <div className="font-medium">{finding.action}</div>
                          <div className="text-muted-foreground">{finding.actor}</div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}
