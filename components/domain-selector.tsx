"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Server, ChevronDown, Plus, Trash2, CheckCircle, Circle, AlertCircle, Wand2, Loader2 } from "lucide-react"
import { invoke, type DomainInfo } from "@/lib/tauri-api"

interface DiscoveredDomainInfo {
  is_domain_joined: boolean
  domain_name: string | null
  netbios_name: string | null
  current_user: string | null
  current_user_upn: string | null
  domain_controller: string | null
  dc_ip_address: string | null
  forest_name: string | null
  site_name: string | null
  suggested_base_dn: string | null
  suggested_server: string | null
  warnings: string[]
}

interface AddDomainForm {
  name: string
  server: string
  username: string
  password: string
  base_dn: string
}

interface DomainSelectorProps {
  onConnectionChange?: (connected: boolean) => void
}

export function DomainSelector({ onConnectionChange }: DomainSelectorProps) {
  const [domains, setDomains] = useState<DomainInfo[]>([])
  const [activeDomain, setActiveDomain] = useState<DomainInfo | null>(null)
  const [showAddDialog, setShowAddDialog] = useState(false)
  const [showDiscoveryPrompt, setShowDiscoveryPrompt] = useState(false)
  const [loading, setLoading] = useState(false)
  const [discovering, setDiscovering] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [discoveredInfo, setDiscoveredInfo] = useState<DiscoveredDomainInfo | null>(null)

  const [newDomain, setNewDomain] = useState<AddDomainForm>({
    name: "",
    server: "",
    username: "",
    password: "",
    base_dn: "",
  })

  useEffect(() => {
    loadDomains()
    checkForDiscoveryPrompt()
  }, [])

  // Check if we should show the discovery prompt on startup
  const checkForDiscoveryPrompt = async () => {
    try {
      const allDomains = await invoke<DomainInfo[]>("get_all_domains")
      if (allDomains.length === 0) {
        // No domains configured - check if machine is domain-joined
        const isDomainJoined = await invoke<boolean>("is_domain_joined")
        if (isDomainJoined) {
          setShowDiscoveryPrompt(true)
        }
      }
    } catch (err) {
      // Discovery prompt check is non-critical
    }
  }

  // Run domain discovery
  const handleDiscovery = async () => {
    setDiscovering(true)
    setError(null)

    try {
      const discovered = await invoke<DiscoveredDomainInfo>("discover_local_domain")
      setDiscoveredInfo(discovered)

      if (discovered.is_domain_joined) {
        // Auto-fill the form with discovered values
        setNewDomain({
          name: discovered.netbios_name || discovered.domain_name || "",
          server: discovered.suggested_server || "",
          username: discovered.current_user_upn || discovered.current_user || "",
          password: "", // User must always enter password
          base_dn: discovered.suggested_base_dn || "",
        })

        // Close discovery prompt if open, open add dialog
        setShowDiscoveryPrompt(false)
        setShowAddDialog(true)
      } else {
        setError("This machine is not joined to a domain. Please enter domain details manually.")
      }
    } catch (err) {
      setError(`Discovery failed: ${err}`)
    } finally {
      setDiscovering(false)
    }
  }

  const loadDomains = async () => {
    try {
      const allDomains = await invoke<DomainInfo[]>("get_all_domains")
      setDomains(allDomains)

      const active = allDomains.find(d => d.is_active)
      setActiveDomain(active || null)
    } catch (err) {
      // Domain loading failure is non-critical; UI shows empty state
    }
  }

  const handleSwitchDomain = async (domainId: number) => {
    setLoading(true)
    setError(null)

    try {
      await invoke("switch_domain", { domainId })
      await loadDomains()
      onConnectionChange?.(true)
    } catch (err) {
      setError(err as string)
      onConnectionChange?.(false)
    } finally {
      setLoading(false)
    }
  }

  const handleAddDomain = async () => {
    if (!newDomain.name || !newDomain.server || !newDomain.username || !newDomain.password || !newDomain.base_dn) {
      setError("All fields are required")
      return
    }

    setLoading(true)
    setError(null)

    try {
      // Test connection first
      const testResult = await invoke<boolean>("test_domain_connection", {
        server: newDomain.server,
        username: newDomain.username,
        password: newDomain.password,
        baseDn: newDomain.base_dn,
      })

      if (!testResult) {
        throw new Error("Connection test failed")
      }

      // Add the domain
      const domainId = await invoke<number>("add_domain", {
        name: newDomain.name,
        server: newDomain.server,
        username: newDomain.username,
        password: newDomain.password,
        baseDn: newDomain.base_dn,
      })

      // Connect to the new domain
      await invoke("switch_domain", { domainId })

      // Reset form and close dialog
      setNewDomain({
        name: "",
        server: "",
        username: "",
        password: "",
        base_dn: "",
      })
      setShowAddDialog(false)

      // Reload domains
      await loadDomains()
      onConnectionChange?.(true)
    } catch (err) {
      setError(err as string)
      onConnectionChange?.(false)
    } finally {
      setLoading(false)
    }
  }

  const handleDeleteDomain = async (domainId: number, domainName: string) => {
    if (!confirm(`Are you sure you want to delete domain "${domainName}"?`)) {
      return
    }

    try {
      await invoke("delete_domain", { domainId })
      await loadDomains()
    } catch (err) {
      setError(err as string)
    }
  }

  const getStatusIcon = (status: DomainInfo["status"]) => {
    if (status === "Connected") {
      return <CheckCircle className="h-3 w-3 text-green-500" />
    } else if (status === "Disconnected") {
      return <Circle className="h-3 w-3 text-gray-400" />
    } else {
      return <AlertCircle className="h-3 w-3 text-red-500" />
    }
  }

  const getStatusText = (status: DomainInfo["status"]) => {
    if (status === "Connected") return "Connected"
    if (status === "Disconnected") return "Disconnected"
    if (typeof status === "object" && "Error" in status) return `Error: ${status.Error}`
    return "Unknown"
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            className="min-w-[200px] justify-between bg-card text-foreground hover:bg-accent"
            disabled={loading}
          >
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4" />
              <span className="truncate">
                {activeDomain ? activeDomain.name : "No Domain"}
              </span>
            </div>
            <ChevronDown className="h-4 w-4 opacity-50" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-[300px]">
          <DropdownMenuLabel>Active Directory Domains</DropdownMenuLabel>
          <DropdownMenuSeparator />

          {domains.length === 0 ? (
            <div className="px-2 py-6 text-center text-sm text-muted-foreground">
              No domains configured
            </div>
          ) : (
            domains.map((domain) => (
              <DropdownMenuItem
                key={domain.id}
                onSelect={() => handleSwitchDomain(domain.id)}
                className="flex items-center justify-between py-3"
              >
                <div className="flex flex-1 flex-col gap-1">
                  <div className="flex items-center gap-2">
                    {getStatusIcon(domain.status)}
                    <span className={`font-medium ${domain.is_active ? "text-primary" : ""}`}>
                      {domain.name}
                    </span>
                  </div>
                  <div className="flex flex-col text-xs text-muted-foreground">
                    <span className="truncate">{domain.server}</span>
                    <span className="truncate">{domain.base_dn}</span>
                  </div>
                </div>
                {!domain.is_active && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 w-6 p-0"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleDeleteDomain(domain.id, domain.name)
                    }}
                  >
                    <Trash2 className="h-3 w-3 text-destructive" />
                  </Button>
                )}
              </DropdownMenuItem>
            ))
          )}

          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setShowAddDialog(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Add New Domain
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Add Domain Dialog */}
      <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle>Add New Domain</DialogTitle>
            <DialogDescription>
              Connect to an Active Directory domain. All fields are required.
            </DialogDescription>
          </DialogHeader>

          {/* Auto-Discover Button */}
          <div className="flex items-center gap-2 rounded-lg border border-dashed p-3">
            <Wand2 className="h-5 w-5 text-muted-foreground" />
            <div className="flex-1">
              <p className="text-sm font-medium">Auto-Discover Domain</p>
              <p className="text-xs text-muted-foreground">
                Automatically detect domain settings from your Windows environment
              </p>
            </div>
            <Button
              variant="secondary"
              size="sm"
              onClick={handleDiscovery}
              disabled={discovering}
            >
              {discovering ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Discovering...
                </>
              ) : (
                "Discover"
              )}
            </Button>
          </div>

          {/* Show discovery warnings if any */}
          {discoveredInfo && discoveredInfo.warnings.length > 0 && (
            <div className="rounded-lg bg-yellow-500/10 p-3 text-sm text-yellow-600 dark:text-yellow-400">
              <p className="font-medium">Discovery Warnings:</p>
              <ul className="mt-1 list-inside list-disc text-xs">
                {discoveredInfo.warnings.map((warning, idx) => (
                  <li key={idx}>{warning}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="name">Domain Name</Label>
              <Input
                id="name"
                placeholder="e.g., Production Domain"
                value={newDomain.name}
                onChange={(e) => setNewDomain({ ...newDomain, name: e.target.value })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="server">Server Address</Label>
              <Input
                id="server"
                placeholder="dc.example.com:389 or dc.example.com:636"
                value={newDomain.server}
                onChange={(e) => setNewDomain({ ...newDomain, server: e.target.value })}
              />
              <p className="text-xs text-muted-foreground">
                Use port 636 for LDAPS (recommended)
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                placeholder="domain\admin or admin@domain.com"
                value={newDomain.username}
                onChange={(e) => setNewDomain({ ...newDomain, username: e.target.value })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={newDomain.password}
                onChange={(e) => setNewDomain({ ...newDomain, password: e.target.value })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="base_dn">Base DN</Label>
              <Input
                id="base_dn"
                placeholder="DC=example,DC=com"
                value={newDomain.base_dn}
                onChange={(e) => setNewDomain({ ...newDomain, base_dn: e.target.value })}
              />
            </div>

            {error && (
              <div className="flex items-center gap-2 rounded-lg bg-destructive/10 p-3 text-sm text-destructive">
                <AlertCircle className="h-4 w-4" />
                {error}
              </div>
            )}
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowAddDialog(false)
                setError(null)
                setDiscoveredInfo(null)
              }}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button onClick={handleAddDomain} disabled={loading}>
              {loading ? "Connecting..." : "Add Domain"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Discovery Prompt Dialog - Shows on startup when no domains and machine is domain-joined */}
      <Dialog open={showDiscoveryPrompt} onOpenChange={setShowDiscoveryPrompt}>
        <DialogContent className="sm:max-w-[450px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              Domain Detected
            </DialogTitle>
            <DialogDescription>
              Your computer appears to be joined to an Active Directory domain.
              Would you like to auto-discover and connect to your domain?
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col gap-4 py-4">
            <div className="rounded-lg bg-muted p-4">
              <div className="flex items-start gap-3">
                <Wand2 className="mt-0.5 h-5 w-5 text-primary" />
                <div>
                  <p className="font-medium">Auto-Discover Domain</p>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Automatically detect your domain controller, base DN, and username
                    from your Windows environment. You&apos;ll only need to enter your password.
                  </p>
                </div>
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 rounded-lg bg-destructive/10 p-3 text-sm text-destructive">
                <AlertCircle className="h-4 w-4" />
                {error}
              </div>
            )}
          </div>

          <DialogFooter className="flex-col gap-2 sm:flex-row">
            <Button
              variant="outline"
              onClick={() => {
                setShowDiscoveryPrompt(false)
                setError(null)
              }}
              disabled={discovering}
              className="w-full sm:w-auto"
            >
              Skip
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                setShowDiscoveryPrompt(false)
                setShowAddDialog(true)
                setError(null)
              }}
              disabled={discovering}
              className="w-full sm:w-auto"
            >
              Manual Setup
            </Button>
            <Button
              onClick={handleDiscovery}
              disabled={discovering}
              className="w-full sm:w-auto"
            >
              {discovering ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Discovering...
                </>
              ) : (
                <>
                  <Wand2 className="mr-2 h-4 w-4" />
                  Auto-Discover
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
