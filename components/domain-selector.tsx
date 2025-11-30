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
import { Server, ChevronDown, Plus, Trash2, CheckCircle, Circle, AlertCircle } from "lucide-react"
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
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [newDomain, setNewDomain] = useState<AddDomainForm>({
    name: "",
    server: "",
    username: "",
    password: "",
    base_dn: "",
  })

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

  const handleSwitchDomain = async (domainId: number) => {
    setLoading(true)
    setError(null)

    try {
      await invoke("switch_domain", { domainId })
      await loadDomains()
      onConnectionChange?.(true)
    } catch (err) {
      setError(err as string)
      console.error("Failed to switch domain:", err)
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
      console.error("Failed to add domain:", err)
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
      console.error("Failed to delete domain:", err)
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
    </>
  )
}
