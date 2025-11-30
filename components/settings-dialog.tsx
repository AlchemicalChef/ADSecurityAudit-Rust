"use client"

import { useState } from "react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Slider } from "@/components/ui/slider"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import {
  Settings,
  Palette,
  Shield,
  Monitor,
  Download,
  Server,
  Bell,
  Clock,
  Database,
  Activity,
  FileText,
  Mail,
  Trash2,
  AlertTriangle,
} from "lucide-react"
import { purgeAllData } from "@/lib/tauri-api"

interface SettingsDialogProps {
  onOpenConnectionDialog?: () => void
}

export function SettingsDialog({ onOpenConnectionDialog }: SettingsDialogProps) {
  // Application Settings
  const [theme, setTheme] = useState<"light" | "dark" | "system">("system")
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [refreshInterval, setRefreshInterval] = useState([30])
  const [notifications, setNotifications] = useState(true)
  const [soundEnabled, setSoundEnabled] = useState(false)

  // Security Settings
  const [sessionTimeout, setSessionTimeout] = useState([30])
  const [auditRetention, setAuditRetention] = useState([90])
  const [riskThreshold, setRiskThreshold] = useState([70])
  const [anomalySensitivity, setAnomalySensitivity] = useState([0.7])

  // Display Settings
  const [dateFormat, setDateFormat] = useState("MM/DD/YYYY")
  const [timeFormat, setTimeFormat] = useState("12h")
  const [timezone, setTimezone] = useState("America/New_York")
  const [compactMode, setCompactMode] = useState(false)

  // Export Settings
  const [defaultExportFormat, setDefaultExportFormat] = useState("csv")
  const [includeTimestamp, setIncludeTimestamp] = useState(true)
  const [emailNotifications, setEmailNotifications] = useState(false)
  const [emailAddress, setEmailAddress] = useState("")

  // Cache Settings
  const [cacheEnabled, setCacheEnabled] = useState(true)
  const [cacheSize, setCacheSize] = useState([100])
  const [cacheTTL, setCacheTTL] = useState([60])

  // Purge state
  const [isPurging, setIsPurging] = useState(false)
  const [purgeMessage, setPurgeMessage] = useState<string | null>(null)

  const handlePurgeData = async () => {
    if (!confirm("Are you sure you want to purge all cached data and connection history? This will disconnect you from Active Directory and clear all stored data. This action cannot be undone.")) {
      return
    }

    setIsPurging(true)
    setPurgeMessage(null)

    try {
      const result = await purgeAllData()
      setPurgeMessage(result)
      // Reload the page to reset the application state
      setTimeout(() => {
        window.location.reload()
      }, 2000)
    } catch (error) {
      setPurgeMessage(`Error: ${error}`)
    } finally {
      setIsPurging(false)
    }
  }

  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <Settings className="mr-2 h-4 w-4" />
          Settings
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-4xl max-h-[90vh]">
        <DialogHeader>
          <DialogTitle>Application Settings</DialogTitle>
          <DialogDescription>
            Configure your IRP Platform preferences and behavior
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="h-[600px] pr-4">
          <Accordion type="multiple" className="w-full" defaultValue={["app", "security", "display"]}>
            {/* Active Directory Connection */}
            <AccordionItem value="ad-connection">
              <AccordionTrigger>
                <div className="flex items-center gap-2">
                  <Server className="h-4 w-4" />
                  <span>Active Directory Connection</span>
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-4 pt-2">
                  <p className="text-sm text-muted-foreground">
                    Manage your Active Directory connection settings and credentials.
                  </p>
                  <Button onClick={onOpenConnectionDialog} className="w-full">
                    <Server className="mr-2 h-4 w-4" />
                    Open AD Connection Manager
                  </Button>
                  <Separator />
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label>Connection Timeout (seconds)</Label>
                      <Input type="number" defaultValue="30" />
                    </div>
                    <div className="space-y-2">
                      <Label>Reconnect Attempts</Label>
                      <Input type="number" defaultValue="3" />
                    </div>
                    <div className="flex items-center justify-between">
                      <Label>Auto-reconnect on failure</Label>
                      <Switch defaultChecked />
                    </div>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>

            {/* Application Settings */}
            <AccordionItem value="app">
              <AccordionTrigger>
                <div className="flex items-center gap-2">
                  <Monitor className="h-4 w-4" />
                  <span>Application Settings</span>
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-6 pt-2">
                  {/* Theme */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <Palette className="h-4 w-4" />
                      <Label className="text-base font-semibold">Appearance</Label>
                    </div>
                    <div className="space-y-2 ml-6">
                      <Label>Theme</Label>
                      <Select value={theme} onValueChange={(v: any) => setTheme(v)}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="light">Light</SelectItem>
                          <SelectItem value="dark">Dark</SelectItem>
                          <SelectItem value="system">System</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <Separator />

                  {/* Auto-refresh */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <Activity className="h-4 w-4" />
                      <Label className="text-base font-semibold">Auto-refresh</Label>
                    </div>
                    <div className="space-y-4 ml-6">
                      <div className="flex items-center justify-between">
                        <Label>Enable auto-refresh</Label>
                        <Switch checked={autoRefresh} onCheckedChange={setAutoRefresh} />
                      </div>
                      {autoRefresh && (
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <Label>Refresh interval (seconds)</Label>
                            <span className="text-sm text-muted-foreground">{refreshInterval[0]}s</span>
                          </div>
                          <Slider
                            value={refreshInterval}
                            onValueChange={setRefreshInterval}
                            min={5}
                            max={300}
                            step={5}
                          />
                        </div>
                      )}
                    </div>
                  </div>

                  <Separator />

                  {/* Notifications */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <Bell className="h-4 w-4" />
                      <Label className="text-base font-semibold">Notifications</Label>
                    </div>
                    <div className="space-y-4 ml-6">
                      <div className="flex items-center justify-between">
                        <Label>Enable notifications</Label>
                        <Switch checked={notifications} onCheckedChange={setNotifications} />
                      </div>
                      <div className="flex items-center justify-between">
                        <Label>Sound alerts</Label>
                        <Switch checked={soundEnabled} onCheckedChange={setSoundEnabled} />
                      </div>
                      <div className="space-y-2">
                        <Label>Notification types</Label>
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-sm">Critical anomalies</span>
                            <Switch defaultChecked />
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-sm">High-risk events</span>
                            <Switch defaultChecked />
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-sm">Audit log events</span>
                            <Switch />
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>

            {/* Security Settings */}
            <AccordionItem value="security">
              <AccordionTrigger>
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  <span>Security Settings</span>
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-6 pt-2">
                  {/* Session */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <Clock className="h-4 w-4" />
                      <Label className="text-base font-semibold">Session Management</Label>
                    </div>
                    <div className="space-y-4 ml-6">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <Label>Session timeout (minutes)</Label>
                          <span className="text-sm text-muted-foreground">{sessionTimeout[0]} min</span>
                        </div>
                        <Slider
                          value={sessionTimeout}
                          onValueChange={setSessionTimeout}
                          min={5}
                          max={120}
                          step={5}
                        />
                      </div>
                      <div className="flex items-center justify-between">
                        <Label>Require re-authentication on timeout</Label>
                        <Switch defaultChecked />
                      </div>
                    </div>
                  </div>

                  <Separator />

                  {/* Audit Log Retention */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      <Label className="text-base font-semibold">Audit Log Retention</Label>
                    </div>
                    <div className="space-y-4 ml-6">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <Label>Retention period (days)</Label>
                          <span className="text-sm text-muted-foreground">{auditRetention[0]} days</span>
                        </div>
                        <Slider
                          value={auditRetention}
                          onValueChange={setAuditRetention}
                          min={7}
                          max={365}
                          step={1}
                        />
                      </div>
                      <div className="flex items-center justify-between">
                        <Label>Auto-archive old logs</Label>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <Label>Encrypt archived logs</Label>
                        <Switch defaultChecked />
                      </div>
                    </div>
                  </div>

                  <Separator />

                  {/* Risk Scoring */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <Activity className="h-4 w-4" />
                      <Label className="text-base font-semibold">Risk Scoring Thresholds</Label>
                    </div>
                    <div className="space-y-4 ml-6">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <Label>Critical risk threshold</Label>
                          <span className="text-sm text-muted-foreground">{riskThreshold[0]}</span>
                        </div>
                        <Slider
                          value={riskThreshold}
                          onValueChange={setRiskThreshold}
                          min={0}
                          max={100}
                          step={1}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Alert on risk level</Label>
                        <Select defaultValue="high">
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="critical">Critical only</SelectItem>
                            <SelectItem value="high">High and above</SelectItem>
                            <SelectItem value="medium">Medium and above</SelectItem>
                            <SelectItem value="all">All levels</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </div>

                  <Separator />

                  {/* Anomaly Detection */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <Bell className="h-4 w-4" />
                      <Label className="text-base font-semibold">Anomaly Detection</Label>
                    </div>
                    <div className="space-y-4 ml-6">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <Label>Detection sensitivity</Label>
                          <span className="text-sm text-muted-foreground">{anomalySensitivity[0].toFixed(1)}</span>
                        </div>
                        <Slider
                          value={anomalySensitivity}
                          onValueChange={setAnomalySensitivity}
                          min={0.1}
                          max={1.0}
                          step={0.1}
                        />
                        <p className="text-xs text-muted-foreground">
                          Lower = fewer false positives, Higher = more detections
                        </p>
                      </div>
                      <div className="flex items-center justify-between">
                        <Label>Real-time detection</Label>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <Label>Baseline auto-update</Label>
                        <Switch defaultChecked />
                      </div>
                    </div>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>

            {/* Display Settings */}
            <AccordionItem value="display">
              <AccordionTrigger>
                <div className="flex items-center gap-2">
                  <Monitor className="h-4 w-4" />
                  <span>Display Settings</span>
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-6 pt-2">
                  {/* Date & Time */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <Clock className="h-4 w-4" />
                      <Label className="text-base font-semibold">Date & Time Format</Label>
                    </div>
                    <div className="space-y-4 ml-6">
                      <div className="space-y-2">
                        <Label>Date format</Label>
                        <Select value={dateFormat} onValueChange={setDateFormat}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="MM/DD/YYYY">MM/DD/YYYY</SelectItem>
                            <SelectItem value="DD/MM/YYYY">DD/MM/YYYY</SelectItem>
                            <SelectItem value="YYYY-MM-DD">YYYY-MM-DD</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label>Time format</Label>
                        <Select value={timeFormat} onValueChange={setTimeFormat}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="12h">12-hour</SelectItem>
                            <SelectItem value="24h">24-hour</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label>Timezone</Label>
                        <Select value={timezone} onValueChange={setTimezone}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="America/New_York">Eastern Time</SelectItem>
                            <SelectItem value="America/Chicago">Central Time</SelectItem>
                            <SelectItem value="America/Denver">Mountain Time</SelectItem>
                            <SelectItem value="America/Los_Angeles">Pacific Time</SelectItem>
                            <SelectItem value="UTC">UTC</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </div>

                  <Separator />

                  {/* Dashboard Layout */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <Monitor className="h-4 w-4" />
                      <Label className="text-base font-semibold">Dashboard Layout</Label>
                    </div>
                    <div className="space-y-4 ml-6">
                      <div className="flex items-center justify-between">
                        <Label>Compact mode</Label>
                        <Switch checked={compactMode} onCheckedChange={setCompactMode} />
                      </div>
                      <div className="space-y-2">
                        <Label>Default view</Label>
                        <Select defaultValue="dashboard">
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="dashboard">Dashboard</SelectItem>
                            <SelectItem value="users">Users</SelectItem>
                            <SelectItem value="audit-logs">Audit Logs</SelectItem>
                            <SelectItem value="anomalies">Anomalies</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label>Items per page</Label>
                        <Select defaultValue="25">
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="10">10</SelectItem>
                            <SelectItem value="25">25</SelectItem>
                            <SelectItem value="50">50</SelectItem>
                            <SelectItem value="100">100</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>

            {/* Export Settings */}
            <AccordionItem value="export">
              <AccordionTrigger>
                <div className="flex items-center gap-2">
                  <Download className="h-4 w-4" />
                  <span>Export Settings</span>
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-6 pt-2">
                  {/* Export Format */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      <Label className="text-base font-semibold">Default Export Format</Label>
                    </div>
                    <div className="space-y-4 ml-6">
                      <div className="space-y-2">
                        <Label>Format</Label>
                        <Select value={defaultExportFormat} onValueChange={setDefaultExportFormat}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="csv">CSV</SelectItem>
                            <SelectItem value="json">JSON</SelectItem>
                            <SelectItem value="xlsx">Excel (XLSX)</SelectItem>
                            <SelectItem value="pdf">PDF Report</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="flex items-center justify-between">
                        <Label>Include timestamp in filename</Label>
                        <Switch checked={includeTimestamp} onCheckedChange={setIncludeTimestamp} />
                      </div>
                      <div className="flex items-center justify-between">
                        <Label>Include metadata</Label>
                        <Switch defaultChecked />
                      </div>
                    </div>
                  </div>

                  <Separator />

                  {/* Email Reports */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <Mail className="h-4 w-4" />
                      <Label className="text-base font-semibold">Email Notifications</Label>
                    </div>
                    <div className="space-y-4 ml-6">
                      <div className="flex items-center justify-between">
                        <Label>Enable email reports</Label>
                        <Switch checked={emailNotifications} onCheckedChange={setEmailNotifications} />
                      </div>
                      {emailNotifications && (
                        <>
                          <div className="space-y-2">
                            <Label>Email address</Label>
                            <Input
                              type="email"
                              placeholder="admin@example.com"
                              value={emailAddress}
                              onChange={(e) => setEmailAddress(e.target.value)}
                            />
                          </div>
                          <div className="space-y-2">
                            <Label>Report frequency</Label>
                            <Select defaultValue="daily">
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="realtime">Real-time</SelectItem>
                                <SelectItem value="hourly">Hourly</SelectItem>
                                <SelectItem value="daily">Daily</SelectItem>
                                <SelectItem value="weekly">Weekly</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>

            {/* Cache Settings */}
            <AccordionItem value="cache">
              <AccordionTrigger>
                <div className="flex items-center gap-2">
                  <Database className="h-4 w-4" />
                  <span>Cache Settings</span>
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-6 pt-2">
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <Database className="h-4 w-4" />
                      <Label className="text-base font-semibold">Cache Configuration</Label>
                    </div>
                    <div className="space-y-4 ml-6">
                      <div className="flex items-center justify-between">
                        <Label>Enable caching</Label>
                        <Switch checked={cacheEnabled} onCheckedChange={setCacheEnabled} />
                      </div>
                      {cacheEnabled && (
                        <>
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <Label>Max cache size (MB)</Label>
                              <span className="text-sm text-muted-foreground">{cacheSize[0]} MB</span>
                            </div>
                            <Slider value={cacheSize} onValueChange={setCacheSize} min={50} max={500} step={10} />
                          </div>
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <Label>Cache TTL (minutes)</Label>
                              <span className="text-sm text-muted-foreground">{cacheTTL[0]} min</span>
                            </div>
                            <Slider value={cacheTTL} onValueChange={setCacheTTL} min={5} max={180} step={5} />
                          </div>
                          <div className="flex items-center justify-between">
                            <Label>Cache warming</Label>
                            <Switch defaultChecked />
                          </div>
                          <div className="flex items-center justify-between">
                            <Label>Auto-cleanup expired entries</Label>
                            <Switch defaultChecked />
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>

            {/* Data Management */}
            <AccordionItem value="data-management">
              <AccordionTrigger>
                <div className="flex items-center gap-2">
                  <Trash2 className="h-4 w-4" />
                  <span>Data Management</span>
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-6 pt-2">
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-destructive" />
                      <Label className="text-base font-semibold text-destructive">Danger Zone</Label>
                    </div>
                    <div className="space-y-4 ml-6">
                      <div className="p-4 border border-destructive/50 rounded-lg bg-destructive/5">
                        <h4 className="font-medium text-destructive mb-2">Purge All Data</h4>
                        <p className="text-sm text-muted-foreground mb-4">
                          Clear all cached data, connection history, and stored domain configurations.
                          Use this if you&apos;re experiencing loading issues or corrupted data.
                          This will disconnect you from Active Directory and require you to reconnect.
                        </p>
                        {purgeMessage && (
                          <div className={`text-sm mb-4 p-2 rounded ${purgeMessage.startsWith('Error') ? 'bg-destructive/10 text-destructive' : 'bg-green-500/10 text-green-600'}`}>
                            {purgeMessage}
                          </div>
                        )}
                        <Button
                          variant="destructive"
                          onClick={handlePurgeData}
                          disabled={isPurging}
                          className="w-full"
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          {isPurging ? "Purging Data..." : "Purge All Data"}
                        </Button>
                      </div>
                    </div>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </ScrollArea>

        <div className="flex items-center justify-between pt-4 border-t">
          <Button variant="outline">Reset to Defaults</Button>
          <div className="flex gap-2">
            <Button variant="outline">Cancel</Button>
            <Button>Save Changes</Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
