/** Cache Statistics Monitor -- real-time LDAP query cache performance metrics. */
"use client"

import { useState, useEffect, useCallback } from "react"
import { invoke } from "@/lib/tauri-api"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { AlertCircle, RefreshCw, Trash2, Zap, ZapOff, Database } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Progress } from "@/components/ui/progress"
import type { CacheStatistics } from "@/lib/advanced-features-types"
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts"

interface CacheStatisticsMonitorProps {
  isConnected: boolean
}

export function CacheStatisticsMonitor({ isConnected }: CacheStatisticsMonitorProps) {
  const [statistics, setStatistics] = useState<CacheStatistics | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(false)

  const fetchStatistics = useCallback(async () => {
    if (!isConnected) {
      setError("Not connected to Active Directory")
      return
    }

    setLoading(true)
    setError(null)

    try {
      const result = await invoke<CacheStatistics>("get_cache_statistics")
      setStatistics(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [isConnected])

  const enableWarming = async () => {
    try {
      await invoke("enable_cache_warming")
      fetchStatistics()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const disableWarming = async () => {
    try {
      await invoke("disable_cache_warming")
      fetchStatistics()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const cleanupCache = async () => {
    try {
      await invoke("cleanup_expired_cache")
      fetchStatistics()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const invalidateCache = async () => {
    try {
      await invoke("invalidate_advanced_cache")
      fetchStatistics()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  useEffect(() => {
    if (isConnected) {
      fetchStatistics()
    }
  }, [isConnected, fetchStatistics])

  useEffect(() => {
    if (autoRefresh && isConnected) {
      const interval = setInterval(fetchStatistics, 5000)
      return () => clearInterval(interval)
    }
  }, [autoRefresh, isConnected, fetchStatistics])

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 B"
    const k = 1024
    const sizes = ["B", "KB", "MB", "GB"]
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
  }

  const pieData = statistics
    ? [
        { name: "Hit", value: statistics.hit_count, color: "#22c55e" },
        { name: "Miss", value: statistics.miss_count, color: "#ef4444" },
      ]
    : []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Cache Statistics</h2>
          <p className="text-muted-foreground">Monitor advanced cache performance and efficiency</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setAutoRefresh(!autoRefresh)}>
            {autoRefresh ? <ZapOff className="mr-2 h-4 w-4" /> : <Zap className="mr-2 h-4 w-4" />}
            {autoRefresh ? "Disable" : "Enable"} Auto-Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={fetchStatistics} disabled={loading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {statistics && (
        <>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Hit Rate</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">
                  {(statistics.hit_rate * 100).toFixed(1)}%
                </div>
                <Progress value={statistics.hit_rate * 100} className="mt-2" />
                <p className="text-xs text-muted-foreground mt-2">
                  {statistics.hit_count.toLocaleString()} hits / {statistics.miss_count.toLocaleString()} misses
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Cache Size</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">
                  {formatBytes(statistics.total_size_bytes)}
                </div>
                <Progress value={(statistics.total_size_bytes / (100 * 1024 * 1024)) * 100} className="mt-2" />
                <p className="text-xs text-muted-foreground mt-2">
                  {statistics.entry_count} entries / 100 MB max
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Cache Entries</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{statistics.entry_count}</div>
                <p className="text-xs text-muted-foreground mt-2">
                  Active cached items
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Evictions</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{statistics.eviction_count}</div>
                <p className="text-xs text-muted-foreground mt-2">
                  Total items evicted
                </p>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Hit vs Miss Distribution</CardTitle>
                <CardDescription>Cache effectiveness visualization</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      label={(entry) => `${entry.name}: ${entry.value}`}
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Cache Performance</CardTitle>
                <CardDescription>Key performance metrics</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium">Total Requests</span>
                    <span className="text-2xl font-bold">
                      {(statistics.hit_count + statistics.miss_count).toLocaleString()}
                    </span>
                  </div>
                  <Progress value={100} className="h-2" />
                </div>

                <div className="border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium">Cache Hits</span>
                    <span className="text-2xl font-bold text-green-500">
                      {statistics.hit_count.toLocaleString()}
                    </span>
                  </div>
                  <Progress value={statistics.hit_rate * 100} className="h-2" />
                </div>

                <div className="border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium">Cache Misses</span>
                    <span className="text-2xl font-bold text-red-500">
                      {statistics.miss_count.toLocaleString()}
                    </span>
                  </div>
                  <Progress value={(1 - statistics.hit_rate) * 100} className="h-2" />
                </div>

                <div className="border rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">Memory Usage</span>
                    <span className="text-lg font-bold">
                      {((statistics.total_size_bytes / (100 * 1024 * 1024)) * 100).toFixed(1)}%
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Cache Management</CardTitle>
              <CardDescription>Control cache behavior and maintenance</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="border rounded-lg p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-semibold">Cache Warming</h4>
                      <p className="text-sm text-muted-foreground">
                        Predictively preload frequently accessed data
                      </p>
                    </div>
                    <Badge variant={statistics.warming_enabled ? "default" : "outline"}>
                      {statistics.warming_enabled ? "Enabled" : "Disabled"}
                    </Badge>
                  </div>
                  <div className="flex gap-2">
                    {statistics.warming_enabled ? (
                      <Button variant="outline" size="sm" onClick={disableWarming}>
                        <ZapOff className="mr-2 h-4 w-4" />
                        Disable Warming
                      </Button>
                    ) : (
                      <Button variant="default" size="sm" onClick={enableWarming}>
                        <Zap className="mr-2 h-4 w-4" />
                        Enable Warming
                      </Button>
                    )}
                  </div>
                </div>

                <div className="border rounded-lg p-4 space-y-3">
                  <div>
                    <h4 className="font-semibold">Cache Maintenance</h4>
                    <p className="text-sm text-muted-foreground">
                      Clean up expired entries or clear entire cache
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={cleanupCache}>
                      <Database className="mr-2 h-4 w-4" />
                      Cleanup Expired
                    </Button>
                    <Button variant="destructive" size="sm" onClick={invalidateCache}>
                      <Trash2 className="mr-2 h-4 w-4" />
                      Clear All
                    </Button>
                  </div>
                </div>
              </div>

              <Alert className="mt-4">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  <strong>Cache Strategy:</strong> LRU (Least Recently Used) eviction with 100MB max size and 1-hour default TTL.
                  Hit rate above 70% indicates good cache effectiveness.
                </AlertDescription>
              </Alert>
            </CardContent>
          </Card>
        </>
      )}

      {!statistics && !loading && (
        <Card>
          <CardContent className="pt-6">
            <div className="text-center text-muted-foreground py-8">
              <Database className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No cache statistics available</p>
              <p className="text-sm">Click Refresh to load statistics</p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
