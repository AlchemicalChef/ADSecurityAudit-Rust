/**
 * Anomaly Detection Panel Component
 *
 * Displays behavioral anomalies detected by the machine learning-inspired
 * analytics engine, providing real-time security monitoring.
 *
 * @module components/anomaly-detection-panel
 *
 * Anomaly Types Displayed:
 * - UnusualLogonTime: Activity outside normal hours
 * - UnusualLogonLocation: Access from atypical IPs
 * - PrivilegeEscalation: Addition to privileged groups
 * - MassGroupChange: Bulk membership modifications
 * - RapidFireLogons: Potential credential stuffing
 * - SuspiciousQuery: Unusual LDAP query patterns
 * - ConfigurationChange: Unexpected AD modifications
 * - BruteForceAttempt: Multiple failed authentications
 * - LateralMovement: Cross-system access patterns
 *
 * Severity Levels:
 * - Critical: Likely security incident, immediate action required
 * - High: Suspicious activity requiring prompt investigation
 * - Medium: Unusual behavior warranting review
 * - Low: Informational, routine monitoring
 *
 * Features:
 * - Real-time anomaly feed with filtering
 * - Confidence scores and deviation metrics
 * - Evidence details for each detection
 * - Recommended response actions
 *
 * @see https://docs.microsoft.com/en-us/defender-for-identity/suspicious-activity-guide
 */
"use client"

import { useState, useEffect } from "react"
import { invoke } from "@tauri-apps/api/core"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { AlertCircle, AlertTriangle, Bell, Shield, Activity, Eye } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Progress } from "@/components/ui/progress"
import type {
  Anomaly,
  AnomalySeverity,
  AnomalyType,
  BehavioralBaseline,
  EntityType,
  LogonEvent,
} from "@/lib/advanced-features-types"
import { format } from "date-fns"

interface AnomalyDetectionPanelProps {
  isConnected: boolean
}

export function AnomalyDetectionPanel({ isConnected }: AnomalyDetectionPanelProps) {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([])
  const [baseline, setBaseline] = useState<BehavioralBaseline | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Detection forms
  const [entity, setEntity] = useState("")
  const [entityType, setEntityType] = useState<EntityType>("user")
  const [logonTimestamp, setLogonTimestamp] = useState("")
  const [sourceIp, setSourceIp] = useState("")

  const severityColors: Record<AnomalySeverity, string> = {
    Critical: "bg-red-500 text-white",
    High: "bg-orange-500 text-white",
    Medium: "bg-yellow-500 text-black",
    Low: "bg-blue-500 text-white",
  }

  const getSeverityIcon = (severity: AnomalySeverity) => {
    switch (severity) {
      case "Critical":
        return <AlertCircle className="h-5 w-5 text-red-500" />
      case "High":
        return <AlertTriangle className="h-5 w-5 text-orange-500" />
      case "Medium":
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />
      case "Low":
        return <Bell className="h-5 w-5 text-blue-500" />
    }
  }

  const getAnomalyTypeDisplay = (type: AnomalyType) => {
    return type.replace(/([A-Z])/g, " $1").trim()
  }

  const detectLogonAnomalies = async () => {
    if (!isConnected || !entity || !logonTimestamp || !sourceIp) {
      setError("Please fill in all required fields")
      return
    }

    setLoading(true)
    setError(null)

    try {
      const logonEvent: LogonEvent = {
        timestamp: new Date(logonTimestamp).toISOString(),
        username: entity,
        source_ip: sourceIp,
        success: true,
      }

      const result = await invoke<Anomaly[]>("detect_logon_anomalies", {
        entity,
        logonEvent,
      })

      if (result.length > 0) {
        setAnomalies((prev) => [...result, ...prev])
      } else {
        setError("No anomalies detected - this logon appears normal")
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  const buildBaseline = async () => {
    if (!isConnected || !entity) {
      setError("Please provide entity name")
      return
    }

    setLoading(true)
    setError(null)

    try {
      // Example logon history - in production, this would come from AD event logs
      const logonHistory: LogonEvent[] = Array.from({ length: 30 }, (_, i) => ({
        timestamp: new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString(),
        username: entity,
        source_ip: `192.168.1.${100 + (i % 50)}`,
        success: true,
      }))

      await invoke("build_behavioral_baseline", {
        entity,
        entityType,
        logonHistory,
      })

      // Fetch the baseline
      const result = await invoke<BehavioralBaseline>("get_behavioral_baseline", {
        entity,
      })
      setBaseline(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  const getBaseline = async () => {
    if (!isConnected || !entity) {
      setError("Please provide entity name")
      return
    }

    setLoading(true)
    setError(null)

    try {
      const result = await invoke<BehavioralBaseline>("get_behavioral_baseline", {
        entity,
      })
      setBaseline(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  const clearAnomalies = () => {
    setAnomalies([])
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Anomaly Detection</h2>
          <p className="text-muted-foreground">Real-time behavioral analysis and threat detection</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-lg">
            {anomalies.length} Active Alerts
          </Badge>
          {anomalies.filter((a) => a.severity === "Critical").length > 0 && (
            <Badge variant="destructive" className="text-lg">
              {anomalies.filter((a) => a.severity === "Critical").length} Critical
            </Badge>
          )}
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Tabs defaultValue="alerts" className="space-y-4">
        <TabsList>
          <TabsTrigger value="alerts">
            <Bell className="mr-2 h-4 w-4" />
            Active Alerts
          </TabsTrigger>
          <TabsTrigger value="detection">
            <Activity className="mr-2 h-4 w-4" />
            Detection
          </TabsTrigger>
          <TabsTrigger value="baseline">
            <Eye className="mr-2 h-4 w-4" />
            Baselines
          </TabsTrigger>
        </TabsList>

        {/* Active Alerts Tab */}
        <TabsContent value="alerts" className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="text-sm text-muted-foreground">
              Showing {anomalies.length} detected anomalies
            </div>
            {anomalies.length > 0 && (
              <Button variant="outline" size="sm" onClick={clearAnomalies}>
                Clear All
              </Button>
            )}
          </div>

          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Total Anomalies</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{anomalies.length}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Critical</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-500">
                  {anomalies.filter((a) => a.severity === "Critical").length}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">High</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-orange-500">
                  {anomalies.filter((a) => a.severity === "High").length}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Avg Confidence</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {anomalies.length > 0
                    ? ((anomalies.reduce((sum, a) => sum + a.confidence, 0) / anomalies.length) * 100).toFixed(0)
                    : 0}
                  %
                </div>
              </CardContent>
            </Card>
          </div>

          <ScrollArea className="h-[600px]">
            <div className="space-y-4">
              {anomalies.length === 0 && (
                <Card>
                  <CardContent className="pt-6">
                    <div className="text-center text-muted-foreground">
                      <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No anomalies detected</p>
                      <p className="text-sm">Your environment is secure</p>
                    </div>
                  </CardContent>
                </Card>
              )}
              {anomalies.map((anomaly) => (
                <Card key={anomaly.id} className="border-l-4" style={{ borderLeftColor: anomaly.severity === "Critical" ? "#ef4444" : anomaly.severity === "High" ? "#f97316" : anomaly.severity === "Medium" ? "#eab308" : "#3b82f6" }}>
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2">
                        {getSeverityIcon(anomaly.severity)}
                        <div>
                          <CardTitle className="text-lg">{getAnomalyTypeDisplay(anomaly.anomaly_type)}</CardTitle>
                          <CardDescription>{anomaly.subject}</CardDescription>
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-2">
                        <Badge className={severityColors[anomaly.severity]}>{anomaly.severity}</Badge>
                        <Badge variant="outline">
                          {(anomaly.confidence * 100).toFixed(0)}% Confidence
                        </Badge>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <div className="text-sm font-medium mb-1">Description</div>
                      <p className="text-sm text-muted-foreground">{anomaly.description}</p>
                    </div>

                    <div>
                      <div className="text-sm font-medium mb-1">Detection Time</div>
                      <p className="text-sm text-muted-foreground">
                        {format(new Date(anomaly.detected_at), "PPpp")}
                      </p>
                    </div>

                    {anomaly.evidence.length > 0 && (
                      <div>
                        <div className="text-sm font-medium mb-2">Evidence</div>
                        <ul className="list-disc list-inside space-y-1">
                          {anomaly.evidence.map((ev, i) => (
                            <li key={i} className="text-sm text-muted-foreground">
                              {ev}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {anomaly.baseline && (
                      <div>
                        <div className="text-sm font-medium mb-1">Baseline</div>
                        <p className="text-sm text-muted-foreground">{anomaly.baseline}</p>
                      </div>
                    )}

                    {anomaly.deviation && (
                      <div>
                        <div className="text-sm font-medium mb-1">Deviation</div>
                        <p className="text-sm text-muted-foreground">{anomaly.deviation}</p>
                      </div>
                    )}

                    {anomaly.recommended_actions.length > 0 && (
                      <div>
                        <div className="text-sm font-medium mb-2">Recommended Actions</div>
                        <div className="space-y-2">
                          {anomaly.recommended_actions.map((action, i) => (
                            <div key={i} className="flex items-start gap-2 text-sm">
                              <Badge variant="outline" className="mt-0.5">
                                {i + 1}
                              </Badge>
                              <span className="text-muted-foreground">{action}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="pt-2">
                      <Progress value={anomaly.confidence * 100} className="h-2" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        {/* Detection Tab */}
        <TabsContent value="detection" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Detect Logon Anomalies</CardTitle>
              <CardDescription>Analyze logon events for unusual patterns</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Entity (Username)</label>
                  <Input placeholder="e.g., jdoe" value={entity} onChange={(e) => setEntity(e.target.value)} />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Entity Type</label>
                  <Select value={entityType} onValueChange={(v) => setEntityType(v as EntityType)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="user">User</SelectItem>
                      <SelectItem value="computer">Computer</SelectItem>
                      <SelectItem value="service_account">Service Account</SelectItem>
                      <SelectItem value="group">Group</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Logon Timestamp</label>
                  <Input
                    type="datetime-local"
                    value={logonTimestamp}
                    onChange={(e) => setLogonTimestamp(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Source IP</label>
                  <Input
                    placeholder="e.g., 192.168.1.100"
                    value={sourceIp}
                    onChange={(e) => setSourceIp(e.target.value)}
                  />
                </div>
              </div>

              <Button
                onClick={detectLogonAnomalies}
                disabled={loading || !isConnected || !entity || !logonTimestamp || !sourceIp}
                className="mt-4"
              >
                <Activity className="mr-2 h-4 w-4" />
                Detect Anomalies
              </Button>
            </CardContent>
          </Card>

          <Alert>
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              Anomaly detection requires a behavioral baseline for the entity. Build a baseline first if this is the first analysis.
            </AlertDescription>
          </Alert>
        </TabsContent>

        {/* Baselines Tab */}
        <TabsContent value="baseline" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Behavioral Baseline Management</CardTitle>
              <CardDescription>Build and manage behavioral profiles for entities</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Entity (Username)</label>
                  <Input placeholder="e.g., jdoe" value={entity} onChange={(e) => setEntity(e.target.value)} />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Entity Type</label>
                  <Select value={entityType} onValueChange={(v) => setEntityType(v as EntityType)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="user">User</SelectItem>
                      <SelectItem value="computer">Computer</SelectItem>
                      <SelectItem value="service_account">Service Account</SelectItem>
                      <SelectItem value="group">Group</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="flex gap-2 mt-4">
                <Button onClick={buildBaseline} disabled={loading || !isConnected || !entity}>
                  <Shield className="mr-2 h-4 w-4" />
                  Build Baseline
                </Button>
                <Button variant="outline" onClick={getBaseline} disabled={loading || !isConnected || !entity}>
                  <Eye className="mr-2 h-4 w-4" />
                  View Baseline
                </Button>
              </div>
            </CardContent>
          </Card>

          {baseline && (
            <Card>
              <CardHeader>
                <CardTitle>Baseline: {baseline.entity}</CardTitle>
                <CardDescription>
                  Type: {baseline.entity_type} | Created: {format(new Date(baseline.created_at), "PP")} | Updated:{" "}
                  {format(new Date(baseline.updated_at), "PP")}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="border rounded-lg p-4">
                    <div className="text-sm font-medium mb-2">Typical Logon Hours</div>
                    <div className="flex flex-wrap gap-1">
                      {baseline.typical_logon_hours.map((hour) => (
                        <Badge key={hour} variant="outline">
                          {hour}:00
                        </Badge>
                      ))}
                    </div>
                  </div>

                  <div className="border rounded-lg p-4">
                    <div className="text-sm font-medium mb-2">Typical Logon Days</div>
                    <div className="flex flex-wrap gap-1">
                      {baseline.typical_logon_days.map((day) => (
                        <Badge key={day} variant="outline">
                          {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][day]}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  <div className="border rounded-lg p-4">
                    <div className="text-sm font-medium mb-2">Average Sessions/Day</div>
                    <div className="text-2xl font-bold">{baseline.average_sessions_per_day.toFixed(1)}</div>
                  </div>

                  <div className="border rounded-lg p-4">
                    <div className="text-sm font-medium mb-2">Failed Logon Threshold</div>
                    <div className="text-2xl font-bold">{baseline.failed_logon_threshold}</div>
                  </div>
                </div>

                <div className="border rounded-lg p-4">
                  <div className="text-sm font-medium mb-2">Typical Source IPs</div>
                  <div className="flex flex-wrap gap-2">
                    {baseline.typical_source_ips.map((ip) => (
                      <Badge key={ip} variant="secondary">
                        {ip}
                      </Badge>
                    ))}
                  </div>
                </div>

                {baseline.group_memberships.length > 0 && (
                  <div className="border rounded-lg p-4">
                    <div className="text-sm font-medium mb-2">Group Memberships</div>
                    <div className="flex flex-wrap gap-2">
                      {baseline.group_memberships.map((group) => (
                        <Badge key={group} variant="outline">
                          {group}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {baseline.privileged && (
                  <Alert>
                    <Shield className="h-4 w-4" />
                    <AlertDescription>
                      This is a <strong>privileged account</strong>. Anomalies will be flagged with higher severity.
                    </AlertDescription>
                  </Alert>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}
