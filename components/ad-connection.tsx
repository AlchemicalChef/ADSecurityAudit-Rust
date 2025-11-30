"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { connectAD, validateCredentials, type ConnectionStatus } from "@/lib/tauri-api"
import { CredentialPrompt, type Credentials } from "@/components/credential-prompt"
import { Server, CheckCircle, AlertCircle, Shield, Lock, Clock, RefreshCw, LogOut, Network, Database } from "lucide-react"
import { invoke } from "@tauri-apps/api/core"

interface DomainInfo {
  id: number
  name: string
  server: string
  base_dn: string
  is_active: boolean
  status: "Connected" | "Disconnected" | { Error: string }
  last_connected: string | null
}

interface ADConnectionProps {
  isConnected: boolean
  onConnectionChange: (connected: boolean, credentials?: Credentials) => void
}

export function ADConnection({ isConnected, onConnectionChange }: ADConnectionProps) {
  const [showCredentialPrompt, setShowCredentialPrompt] = useState(false)
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [domains, setDomains] = useState<DomainInfo[]>([])
  const [activeDomain, setActiveDomain] = useState<DomainInfo | null>(null)

  useEffect(() => {
    loadDomains()
  }, [])

  const loadDomains = async () => {
    try {
      const allDomains = await invoke<DomainInfo[]>("get_all_domains")
      setDomains(allDomains)

      const active = allDomains.find(d => d.is_active)
      setActiveDomain(active || null)
    } catch (err) {
      console.error("Failed to load domains:", err)
    }
  }

  const handleCredentialSubmit = async (credentials: Credentials) => {
    setError(null)
    setSuccess(null)

    const validationResult = await validateCredentials(credentials.server, credentials.username, credentials.password)

    if (!validationResult.valid) {
      throw new Error(validationResult.error || "Invalid credentials")
    }

    const message = await connectAD(credentials.server, credentials.username, credentials.password, credentials.baseDn)

    setSuccess(message)
    setConnectionStatus({
      connected: true,
      server: credentials.server,
      username: credentials.username,
      baseDn: credentials.baseDn,
      connectedAt: new Date().toISOString(),
      useLdaps: credentials.useLdaps,
    })
    onConnectionChange(true, credentials)
  }

  const handleDisconnect = () => {
    setConnectionStatus(null)
    setSuccess(null)
    setError(null)
    onConnectionChange(false)
  }

  const formatConnectionTime = (isoString: string) => {
    const date = new Date(isoString)
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-foreground">Active Directory Connection</h2>
        <p className="text-sm text-muted-foreground">
          Securely connect to your Active Directory server with domain admin credentials
        </p>
      </div>

      {/* Multi-Domain Overview Card */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-foreground">
            <Network className="h-5 w-5" />
            Multi-Domain Management
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div className="rounded-lg border border-border bg-background p-4">
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Database className="h-4 w-4" />
                  Total Domains
                </div>
                <div className="mt-2 text-2xl font-bold text-foreground">{domains.length}</div>
              </div>
              <div className="rounded-lg border border-border bg-background p-4">
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <CheckCircle className="h-4 w-4" />
                  Connected
                </div>
                <div className="mt-2 text-2xl font-bold text-success">
                  {domains.filter(d => d.status === "Connected").length}
                </div>
              </div>
              <div className="rounded-lg border border-border bg-background p-4">
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Server className="h-4 w-4" />
                  Active
                </div>
                <div className="mt-2 text-2xl font-bold text-primary">
                  {activeDomain ? activeDomain.name : "None"}
                </div>
              </div>
            </div>

            {activeDomain && activeDomain.status === "Connected" && (
              <div className="rounded-lg border border-success/20 bg-success/5 p-4">
                <div className="flex items-center gap-2 text-success mb-3">
                  <CheckCircle className="h-4 w-4" />
                  <span className="font-medium">Active Domain Connection</span>
                </div>
                <div className="grid gap-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Domain:</span>
                    <span className="font-mono text-foreground">{activeDomain.name}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Server:</span>
                    <span className="font-mono text-foreground">{activeDomain.server}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Base DN:</span>
                    <span className="font-mono text-foreground">{activeDomain.base_dn}</span>
                  </div>
                  {activeDomain.last_connected && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Last Connected:</span>
                      <span className="text-foreground">{new Date(activeDomain.last_connected).toLocaleString()}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Legacy Connection Status Card */}
      <Card className="border-border bg-card">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-foreground">
              <Server className="h-5 w-5" />
              Legacy Connection (Deprecated)
            </CardTitle>
            {isConnected && (
              <div className="flex items-center gap-2 rounded-full bg-success/10 px-3 py-1 text-sm text-success">
                <CheckCircle className="h-4 w-4" />
                Connected
              </div>
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            This connection method is deprecated. Use the domain selector in the header to manage multiple domains.
          </p>
        </CardHeader>
        <CardContent>
          {isConnected && connectionStatus ? (
            <div className="space-y-4">
              {/* Connection details */}
              <div className="rounded-lg border border-border bg-background p-4">
                <div className="grid gap-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Server</span>
                    <span className="font-mono text-sm text-foreground">{connectionStatus.server}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Authenticated As</span>
                    <span className="font-mono text-sm text-foreground">{connectionStatus.username}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Base DN</span>
                    <span className="font-mono text-sm text-foreground">{connectionStatus.baseDn}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Connection Type</span>
                    <div className="flex items-center gap-1">
                      <Lock className={`h-3 w-3 ${connectionStatus.useLdaps ? "text-success" : "text-warning"}`} />
                      <span className={`text-sm ${connectionStatus.useLdaps ? "text-success" : "text-warning"}`}>
                        {connectionStatus.useLdaps ? "LDAPS (Secure)" : "LDAP"}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Connected At</span>
                    <div className="flex items-center gap-1 text-sm text-foreground">
                      <Clock className="h-3 w-3" />
                      {formatConnectionTime(connectionStatus.connectedAt)}
                    </div>
                  </div>
                </div>
              </div>

              {/* Action buttons */}
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  className="flex-1 bg-transparent"
                  onClick={() => setShowCredentialPrompt(true)}
                >
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Reconnect
                </Button>
                <Button variant="destructive" className="flex-1" onClick={handleDisconnect}>
                  <LogOut className="mr-2 h-4 w-4" />
                  Disconnect
                </Button>
              </div>

              {success && (
                <div className="flex items-center gap-2 rounded-lg bg-success/10 p-3 text-sm text-success">
                  <CheckCircle className="h-4 w-4" />
                  {success}
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center py-8">
              <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-muted">
                <Shield className="h-8 w-8 text-muted-foreground" />
              </div>
              <p className="mb-2 text-lg font-medium text-foreground">Not Connected</p>
              <p className="mb-6 text-center text-sm text-muted-foreground">
                Connect to Active Directory to manage user accounts and respond to security incidents
              </p>
              <Button onClick={() => setShowCredentialPrompt(true)} className="bg-primary">
                <Lock className="mr-2 h-4 w-4" />
                Enter Credentials
              </Button>

              {error && (
                <div className="mt-4 flex items-center gap-2 rounded-lg bg-destructive/10 p-3 text-sm text-destructive">
                  <AlertCircle className="h-4 w-4" />
                  {error}
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Security Guidelines Card */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-foreground">
            <Shield className="h-5 w-5 text-primary" />
            Security Best Practices
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <div className="flex items-start gap-3">
            <div className="mt-0.5 flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-xs font-medium text-primary">
              1
            </div>
            <div>
              <p className="font-medium text-foreground">Use LDAPS Connection</p>
              <p>Always use LDAPS (port 636) to encrypt credential transmission</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <div className="mt-0.5 flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-xs font-medium text-primary">
              2
            </div>
            <div>
              <p className="font-medium text-foreground">Dedicated Service Account</p>
              <p>Use a service account with only the minimum required permissions</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <div className="mt-0.5 flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-xs font-medium text-primary">
              3
            </div>
            <div>
              <p className="font-medium text-foreground">Credential Security</p>
              <p>Credentials are stored in memory only and cleared on disconnect</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <div className="mt-0.5 flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-xs font-medium text-primary">
              4
            </div>
            <div>
              <p className="font-medium text-foreground">Audit Logging</p>
              <p>All AD operations are logged for compliance and security auditing</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <div className="mt-0.5 flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-xs font-medium text-primary">
              5
            </div>
            <div>
              <p className="font-medium text-foreground">Session Timeout</p>
              <p>Sessions automatically expire after 30 minutes of inactivity</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Credential Prompt Dialog */}
      <CredentialPrompt
        open={showCredentialPrompt}
        onOpenChange={setShowCredentialPrompt}
        onSubmit={handleCredentialSubmit}
        savedServer={connectionStatus?.server}
        savedUsername={connectionStatus?.username}
        savedBaseDn={connectionStatus?.baseDn}
      />
    </div>
  )
}
