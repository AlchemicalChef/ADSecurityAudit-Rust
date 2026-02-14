/** Performance Monitor -- real-time connection pool, cache, and parallel execution metrics. */
"use client"

import { useState, useEffect, useCallback } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Activity,
  Database,
  Cpu,
  HardDrive,
  RefreshCw,
  Trash2,
  Zap,
  TrendingUp,
  AlertCircle,
  CheckCircle2,
  Clock,
  Gauge,
  Play,
  Loader2,
} from "lucide-react"
import {
  getPerformanceStats,
  invalidateCache,
  runComprehensiveAudit,
  type PerformanceStats,
  type ComprehensiveAuditResult,
} from "@/lib/tauri-api"

interface PerformanceMonitorProps {
  isConnected: boolean
}

export function PerformanceMonitor({ isConnected }: PerformanceMonitorProps) {
  const [stats, setStats] = useState<PerformanceStats | null>(null)
  const [loading, setLoading] = useState(false)
  const [auditRunning, setAuditRunning] = useState(false)
  const [auditResult, setAuditResult] = useState<ComprehensiveAuditResult | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null)

  const fetchStats = useCallback(async () => {
    if (!isConnected) return
    setLoading(true)
    try {
      const data = await getPerformanceStats()
      setStats(data)
      setLastRefresh(new Date())
    } catch (error) {
      // Stats fetch failure; loading state reset in finally block
    } finally {
      setLoading(false)
    }
  }, [isConnected])

  useEffect(() => {
    if (isConnected) {
      fetchStats()
    }
  }, [isConnected, fetchStats])

  useEffect(() => {
    let interval: NodeJS.Timeout | null = null
    if (autoRefresh && isConnected) {
      interval = setInterval(fetchStats, 5000)
    }
    return () => {
      if (interval) clearInterval(interval)
    }
  }, [autoRefresh, isConnected, fetchStats])

  const handleClearCache = async () => {
    try {
      await invalidateCache()
      await fetchStats()
    } catch (error) {
      // Cache clear failure is non-critical
    }
  }

  const handleRunComprehensiveAudit = async () => {
    setAuditRunning(true)
    setAuditResult(null)
    try {
      const result = await runComprehensiveAudit()
      setAuditResult(result)
      await fetchStats()
    } catch (error) {
      // Audit failure; running state reset in finally block
    } finally {
      setAuditRunning(false)
    }
  }

  const getCombinedHitRate = () => {
    if (!stats) return 0
    const totalHits = stats.cache.results_hits + stats.cache.realtime_hits
    const totalMisses = stats.cache.results_misses + stats.cache.realtime_misses
    const total = totalHits + totalMisses
    return total > 0 ? totalHits / total : 0
  }

  const getCombinedHits = () => {
    if (!stats) return 0
    return stats.cache.results_hits + stats.cache.realtime_hits
  }

  const getCombinedMisses = () => {
    if (!stats) return 0
    return stats.cache.results_misses + stats.cache.realtime_misses
  }

  const getCombinedSize = () => {
    if (!stats) return 0
    return stats.cache.results_size + stats.cache.realtime_size
  }

  if (!isConnected) {
    return (
      <div className="flex h-full items-center justify-center">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <Activity className="mx-auto h-12 w-12 text-muted-foreground" />
            <CardTitle>Performance Monitor</CardTitle>
            <CardDescription>Connect to Active Directory to view performance metrics</CardDescription>
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
          <h2 className="text-2xl font-bold text-foreground">Performance Monitor</h2>
          <p className="text-muted-foreground">Connection pooling, caching, and parallel execution metrics</p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={autoRefresh ? "bg-primary/10" : ""}
          >
            <Activity className={`mr-2 h-4 w-4 ${autoRefresh ? "animate-pulse" : ""}`} />
            {autoRefresh ? "Auto-Refresh On" : "Auto-Refresh Off"}
          </Button>
          <Button variant="outline" size="sm" onClick={fetchStats} disabled={loading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={handleClearCache}>
            <Trash2 className="mr-2 h-4 w-4" />
            Clear Cache
          </Button>
        </div>
      </div>

      {lastRefresh && <p className="text-xs text-muted-foreground">Last updated: {lastRefresh.toLocaleTimeString()}</p>}

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="connections">Connection Pool</TabsTrigger>
          <TabsTrigger value="cache">Cache</TabsTrigger>
          <TabsTrigger value="executor">Parallel Executor</TabsTrigger>
          <TabsTrigger value="comprehensive">Comprehensive Audit</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          {stats && (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {/* Connection Pool Summary */}
              <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm font-medium">Active Connections</CardTitle>
                  <Database className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stats.connection_pool?.current_active ?? 0}</div>
                  <p className="text-xs text-muted-foreground">Peak: {stats.connection_pool?.peak_active ?? 0}</p>
                  <Progress value={((stats.connection_pool?.current_active ?? 0) / 10) * 100} className="mt-2 h-1" />
                </CardContent>
              </Card>

              {/* Cache Hit Rate - Updated to use combined stats */}
              <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm font-medium">Cache Hit Rate</CardTitle>
                  <Zap className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{(getCombinedHitRate() * 100).toFixed(1)}%</div>
                  <p className="text-xs text-muted-foreground">
                    {getCombinedHits()} hits / {getCombinedMisses()} misses
                  </p>
                  <Progress value={getCombinedHitRate() * 100} className="mt-2 h-1" />
                </CardContent>
              </Card>

              {/* Parallel Efficiency */}
              <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm font-medium">Parallel Efficiency</CardTitle>
                  <Cpu className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stats.executor.parallel_efficiency.toFixed(1)}x</div>
                  <p className="text-xs text-muted-foreground">Speedup vs sequential</p>
                  <Progress
                    value={Math.min((stats.executor.parallel_efficiency / 5) * 100, 100)}
                    className="mt-2 h-1"
                  />
                </CardContent>
              </Card>

              {/* Average Query Time */}
              <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm font-medium">Avg Query Time</CardTitle>
                  <Clock className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stats.connection_pool?.avg_query_time_ms.toFixed(0) ?? 0}ms</div>
                  <p className="text-xs text-muted-foreground">
                    {stats.connection_pool?.total_queries ?? 0} total queries
                  </p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Quick Actions */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Quick Actions</CardTitle>
              <CardDescription>Manage performance and run audits</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 md:grid-cols-3">
              <Button
                variant="outline"
                className="h-auto flex-col gap-2 py-4 bg-transparent"
                onClick={handleClearCache}
              >
                <Trash2 className="h-5 w-5" />
                <span>Clear All Caches</span>
                <span className="text-xs text-muted-foreground">Force fresh data</span>
              </Button>
              <Button
                variant="outline"
                className="h-auto flex-col gap-2 py-4 bg-transparent"
                onClick={handleRunComprehensiveAudit}
                disabled={auditRunning}
              >
                {auditRunning ? <Loader2 className="h-5 w-5 animate-spin" /> : <Play className="h-5 w-5" />}
                <span>Run All Audits</span>
                <span className="text-xs text-muted-foreground">Parallel execution</span>
              </Button>
              <Button
                variant="outline"
                className="h-auto flex-col gap-2 py-4 bg-transparent"
                onClick={() => setAutoRefresh(!autoRefresh)}
              >
                <Activity className={`h-5 w-5 ${autoRefresh ? "text-primary" : ""}`} />
                <span>{autoRefresh ? "Disable" : "Enable"} Auto-Refresh</span>
                <span className="text-xs text-muted-foreground">Every 5 seconds</span>
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="connections" className="space-y-4">
          {stats?.connection_pool && (
            <div className="grid gap-4 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Database className="h-5 w-5" />
                    Connection Pool Status
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm text-muted-foreground">Active</p>
                      <p className="text-2xl font-bold">{stats.connection_pool.current_active}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Peak</p>
                      <p className="text-2xl font-bold">{stats.connection_pool.peak_active}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Created</p>
                      <p className="text-2xl font-bold">{stats.connection_pool.connections_created}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Reused</p>
                      <p className="text-2xl font-bold text-green-500">{stats.connection_pool.connections_reused}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Gauge className="h-5 w-5" />
                    Query Performance
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm text-muted-foreground">Total Queries</p>
                      <p className="text-2xl font-bold">{stats.connection_pool.total_queries}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Avg Time</p>
                      <p className="text-2xl font-bold">{stats.connection_pool.avg_query_time_ms.toFixed(0)}ms</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Failed</p>
                      <p
                        className={`text-2xl font-bold ${stats.connection_pool.connections_failed > 0 ? "text-destructive" : "text-green-500"}`}
                      >
                        {stats.connection_pool.connections_failed}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Reuse Rate</p>
                      <p className="text-2xl font-bold">
                        {(
                          (stats.connection_pool.connections_reused /
                            Math.max(
                              stats.connection_pool.connections_created + stats.connection_pool.connections_reused,
                              1,
                            )) *
                          100
                        ).toFixed(0)}
                        %
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          <Alert>
            <TrendingUp className="h-4 w-4" />
            <AlertTitle>Connection Pooling Benefits</AlertTitle>
            <AlertDescription>
              Connection pooling reduces LDAP bind overhead by reusing established connections. High reuse rates
              indicate efficient connection management. Target: {">"} 80% reuse rate.
            </AlertDescription>
          </Alert>
        </TabsContent>

        <TabsContent value="cache" className="space-y-4">
          {stats && (
            <div className="grid gap-4 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <HardDrive className="h-5 w-5" />
                    Results Cache (5 min TTL)
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm text-muted-foreground">Cached Items</p>
                      <p className="text-2xl font-bold">{stats.cache.results_size}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Hit Rate</p>
                      <p className="text-2xl font-bold text-green-500">
                        {(stats.cache.results_hit_rate * 100).toFixed(1)}%
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Cache Hits</p>
                      <p className="text-2xl font-bold text-green-500">{stats.cache.results_hits}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Cache Misses</p>
                      <p className="text-2xl font-bold text-amber-500">{stats.cache.results_misses}</p>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Hit Rate</span>
                      <span>{(stats.cache.results_hit_rate * 100).toFixed(1)}%</span>
                    </div>
                    <Progress value={stats.cache.results_hit_rate * 100} className="h-2" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Zap className="h-5 w-5" />
                    Realtime Cache (30 sec TTL)
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm text-muted-foreground">Cached Items</p>
                      <p className="text-2xl font-bold">{stats.cache.realtime_size}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Hit Rate</p>
                      <p className="text-2xl font-bold text-green-500">
                        {(stats.cache.realtime_hit_rate * 100).toFixed(1)}%
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Cache Hits</p>
                      <p className="text-2xl font-bold text-green-500">{stats.cache.realtime_hits}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Cache Misses</p>
                      <p className="text-2xl font-bold text-amber-500">{stats.cache.realtime_misses}</p>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Hit Rate</span>
                      <span>{(stats.cache.realtime_hit_rate * 100).toFixed(1)}%</span>
                    </div>
                    <Progress value={stats.cache.realtime_hit_rate * 100} className="h-2" />
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Cache Configuration</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex justify-between rounded-lg bg-muted/50 p-3">
                <span className="text-sm">Audit Results TTL</span>
                <Badge variant="secondary">5 minutes</Badge>
              </div>
              <div className="flex justify-between rounded-lg bg-muted/50 p-3">
                <span className="text-sm">Realtime Data TTL</span>
                <Badge variant="secondary">30 seconds</Badge>
              </div>
              <div className="flex justify-between rounded-lg bg-muted/50 p-3">
                <span className="text-sm">User Search TTL</span>
                <Badge variant="secondary">30 seconds</Badge>
              </div>
              <Button variant="destructive" size="sm" className="w-full" onClick={handleClearCache}>
                <Trash2 className="mr-2 h-4 w-4" />
                Clear All Caches
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="executor" className="space-y-4">
          {stats && (
            <div className="grid gap-4 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Cpu className="h-5 w-5" />
                    Parallel Execution Stats
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm text-muted-foreground">Total Operations</p>
                      <p className="text-2xl font-bold">{stats.executor.total_operations}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Successful</p>
                      <p className="text-2xl font-bold text-green-500">{stats.executor.successful}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Failed</p>
                      <p
                        className={`text-2xl font-bold ${stats.executor.failed > 0 ? "text-destructive" : "text-green-500"}`}
                      >
                        {stats.executor.failed}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Avg Time</p>
                      <p className="text-2xl font-bold">{stats.executor.avg_operation_ms.toFixed(0)}ms</p>
                    </div>
                  </div>
                  {stats.executor.last_execution && (
                    <p className="text-xs text-muted-foreground">
                      Last execution: {new Date(stats.executor.last_execution).toLocaleString()}
                    </p>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Zap className="h-5 w-5" />
                    Efficiency Metrics
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="text-center">
                    <p className="text-4xl font-bold text-primary">{stats.executor.parallel_efficiency.toFixed(1)}x</p>
                    <p className="text-sm text-muted-foreground">Parallel Speedup</p>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Efficiency Rating</span>
                      <span>
                        {stats.executor.parallel_efficiency >= 3
                          ? "Excellent"
                          : stats.executor.parallel_efficiency >= 2
                            ? "Good"
                            : "Fair"}
                      </span>
                    </div>
                    <Progress value={Math.min((stats.executor.parallel_efficiency / 5) * 100, 100)} className="h-2" />
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Total execution time: {(stats.executor.total_duration_ms / 1000).toFixed(1)}s
                  </p>
                </CardContent>
              </Card>
            </div>
          )}

          <Alert>
            <Cpu className="h-4 w-4" />
            <AlertTitle>Parallel Execution</AlertTitle>
            <AlertDescription>
              Audits run concurrently using tokio::join! for maximum efficiency. A parallel efficiency of 3x+ means
              queries that would take 30 seconds sequentially complete in under 10 seconds.
            </AlertDescription>
          </Alert>
        </TabsContent>

        <TabsContent value="comprehensive" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Play className="h-5 w-5" />
                Comprehensive Security Audit
              </CardTitle>
              <CardDescription>
                Run all security audits in parallel for a complete assessment of your Active Directory environment.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button className="w-full" size="lg" onClick={handleRunComprehensiveAudit} disabled={auditRunning}>
                {auditRunning ? (
                  <>
                    <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                    Running All Audits...
                  </>
                ) : (
                  <>
                    <Play className="mr-2 h-5 w-5" />
                    Run Comprehensive Audit
                  </>
                )}
              </Button>

              {auditResult && (
                <div className="space-y-4">
                  <div className="grid gap-2 md:grid-cols-4">
                    <div className="rounded-lg bg-muted/50 p-3 text-center">
                      <p className="text-2xl font-bold text-green-500">
                        {
                          [
                            auditResult.domain_security,
                            auditResult.gpo_audit,
                            auditResult.delegation_audit,
                            auditResult.trust_audit,
                            auditResult.permissions_audit,
                            auditResult.group_audit,
                            auditResult.da_equivalence_audit,
                          ].filter(Boolean).length
                        }
                      </p>
                      <p className="text-xs text-muted-foreground">Audits Completed</p>
                    </div>
                    <div className="rounded-lg bg-muted/50 p-3 text-center">
                      <p className="text-2xl font-bold text-destructive">{auditResult.errors.length}</p>
                      <p className="text-xs text-muted-foreground">Errors</p>
                    </div>
                    <div className="rounded-lg bg-muted/50 p-3 text-center">
                      <p className="text-2xl font-bold">
                        {auditResult.execution_stats.parallel_efficiency.toFixed(1)}x
                      </p>
                      <p className="text-xs text-muted-foreground">Efficiency</p>
                    </div>
                    <div className="rounded-lg bg-muted/50 p-3 text-center">
                      <p className="text-2xl font-bold">
                        {(auditResult.execution_stats.total_duration_ms / 1000).toFixed(1)}s
                      </p>
                      <p className="text-xs text-muted-foreground">Total Time</p>
                    </div>
                  </div>

                  {auditResult.errors.length > 0 && (
                    <Alert variant="destructive">
                      <AlertCircle className="h-4 w-4" />
                      <AlertTitle>Audit Errors</AlertTitle>
                      <AlertDescription>
                        <ul className="list-disc list-inside">
                          {auditResult.errors.map((error, idx) => (
                            <li key={idx}>{error}</li>
                          ))}
                        </ul>
                      </AlertDescription>
                    </Alert>
                  )}

                  <div className="grid gap-2 md:grid-cols-2 lg:grid-cols-4">
                    {auditResult.domain_security && (
                      <div className="flex items-center gap-2 rounded-lg border p-3">
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                        <span className="text-sm">Domain Security</span>
                      </div>
                    )}
                    {auditResult.gpo_audit && (
                      <div className="flex items-center gap-2 rounded-lg border p-3">
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                        <span className="text-sm">GPO Audit</span>
                      </div>
                    )}
                    {auditResult.delegation_audit && (
                      <div className="flex items-center gap-2 rounded-lg border p-3">
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                        <span className="text-sm">Delegation Audit</span>
                      </div>
                    )}
                    {auditResult.trust_audit && (
                      <div className="flex items-center gap-2 rounded-lg border p-3">
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                        <span className="text-sm">Trust Audit</span>
                      </div>
                    )}
                    {auditResult.permissions_audit && (
                      <div className="flex items-center gap-2 rounded-lg border p-3">
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                        <span className="text-sm">Permissions Audit</span>
                      </div>
                    )}
                    {auditResult.group_audit && (
                      <div className="flex items-center gap-2 rounded-lg border p-3">
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                        <span className="text-sm">Group Audit</span>
                      </div>
                    )}
                    {auditResult.da_equivalence_audit && (
                      <div className="flex items-center gap-2 rounded-lg border p-3">
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                        <span className="text-sm">DA Equivalence</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
