"use client"

import type React from "react"

import { useState, useEffect, useCallback } from "react"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Shield, Eye, EyeOff, Lock, AlertTriangle, CheckCircle2, Info, KeyRound } from "lucide-react"

export interface Credentials {
  server: string
  username: string
  password: string
  baseDn: string
  useLdaps: boolean
}

interface CredentialPromptProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSubmit: (credentials: Credentials) => Promise<void>
  title?: string
  description?: string
  isReauthentication?: boolean
  savedServer?: string
  savedUsername?: string
  savedBaseDn?: string
}

interface PasswordStrength {
  score: number
  label: string
  color: string
}

export function CredentialPrompt({
  open,
  onOpenChange,
  onSubmit,
  title = "Domain Admin Authentication",
  description = "Enter your Active Directory domain administrator credentials to establish a secure connection.",
  isReauthentication = false,
  savedServer = "",
  savedUsername = "",
  savedBaseDn = "",
}: CredentialPromptProps) {
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [useLdaps, setUseLdaps] = useState(true)

  // Form state
  const [server, setServer] = useState(savedServer)
  const [username, setUsername] = useState(savedUsername)
  const [password, setPassword] = useState("")
  const [baseDn, setBaseDn] = useState(savedBaseDn)

  // Validation state
  const [serverValid, setServerValid] = useState<boolean | null>(null)
  const [usernameValid, setUsernameValid] = useState<boolean | null>(null)
  const [baseDnValid, setBaseDnValid] = useState<boolean | null>(null)

  // Reset form when dialog opens
  useEffect(() => {
    if (open) {
      setPassword("")
      setError(null)
      setShowPassword(false)
      if (!isReauthentication) {
        setServer(savedServer)
        setUsername(savedUsername)
        setBaseDn(savedBaseDn)
      }
    }
  }, [open, isReauthentication, savedServer, savedUsername, savedBaseDn])

  // Validate server format
  const validateServer = useCallback((value: string) => {
    if (!value) return null
    // Match hostname:port or hostname format
    const serverRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*(:[\d]+)?$/
    return serverRegex.test(value)
  }, [])

  // Validate username format (DN or UPN)
  const validateUsername = useCallback((value: string) => {
    if (!value) return null
    // Match DN format or UPN format
    const dnRegex = /^CN=.+,.*DC=.+$/i
    const upnRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
    const samRegex = /^[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+$/
    return dnRegex.test(value) || upnRegex.test(value) || samRegex.test(value)
  }, [])

  // Validate Base DN format
  const validateBaseDn = useCallback((value: string) => {
    if (!value) return null
    const baseDnRegex = /^DC=[a-zA-Z0-9-]+(,DC=[a-zA-Z0-9-]+)*$/i
    return baseDnRegex.test(value)
  }, [])

  // Update validation states
  useEffect(() => {
    setServerValid(validateServer(server))
  }, [server, validateServer])

  useEffect(() => {
    setUsernameValid(validateUsername(username))
  }, [username, validateUsername])

  useEffect(() => {
    setBaseDnValid(validateBaseDn(baseDn))
  }, [baseDn, validateBaseDn])

  const getPasswordStrength = (pwd: string): PasswordStrength => {
    if (!pwd) return { score: 0, label: "", color: "" }

    let score = 0
    if (pwd.length >= 8) score++
    if (pwd.length >= 12) score++
    if (/[A-Z]/.test(pwd)) score++
    if (/[a-z]/.test(pwd)) score++
    if (/[0-9]/.test(pwd)) score++
    if (/[^A-Za-z0-9]/.test(pwd)) score++

    if (score <= 2) return { score, label: "Weak", color: "bg-destructive" }
    if (score <= 4) return { score, label: "Medium", color: "bg-warning" }
    return { score, label: "Strong", color: "bg-success" }
  }

  const passwordStrength = getPasswordStrength(password)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    // Validate all fields
    if (!validateServer(server)) {
      setError("Invalid server format. Use hostname:port or hostname")
      setLoading(false)
      return
    }

    if (!validateUsername(username)) {
      setError("Invalid username format. Use DN, UPN (user@domain.com), or DOMAIN\\user format")
      setLoading(false)
      return
    }

    if (!validateBaseDn(baseDn)) {
      setError("Invalid Base DN format. Use DC=domain,DC=com format")
      setLoading(false)
      return
    }

    if (!password) {
      setError("Password is required")
      setLoading(false)
      return
    }

    try {
      // Construct server URL based on LDAPS selection
      const serverUrl = useLdaps
        ? server.includes(":")
          ? server
          : `${server}:636`
        : server.includes(":")
          ? server
          : `${server}:389`

      await onSubmit({
        server: serverUrl,
        username,
        password,
        baseDn,
        useLdaps,
      })

      // Clear sensitive data from memory
      setPassword("")
      onOpenChange(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed")
    } finally {
      setLoading(false)
    }
  }

  const ValidationIcon = ({ valid }: { valid: boolean | null }) => {
    if (valid === null) return null
    if (valid) return <CheckCircle2 className="h-4 w-4 text-success" />
    return <AlertTriangle className="h-4 w-4 text-destructive" />
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card sm:max-w-[500px]">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            <div>
              <DialogTitle className="text-foreground">{title}</DialogTitle>
              <DialogDescription className="text-muted-foreground">{description}</DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4 pt-4">
          {/* Security indicator */}
          <div className="flex items-center gap-2 rounded-lg bg-primary/5 p-3 text-sm">
            <Lock className="h-4 w-4 text-primary" />
            <span className="text-muted-foreground">Credentials are encrypted in transit and never stored on disk</span>
          </div>

          {!isReauthentication && (
            <>
              {/* Server input */}
              <div className="space-y-2">
                <Label htmlFor="cred-server" className="flex items-center justify-between text-foreground">
                  LDAP Server
                  <ValidationIcon valid={serverValid} />
                </Label>
                <Input
                  id="cred-server"
                  value={server}
                  onChange={(e) => setServer(e.target.value)}
                  placeholder="ldap.company.com"
                  className="bg-background"
                  autoComplete="off"
                  spellCheck={false}
                />
                <p className="text-xs text-muted-foreground">
                  Port will be auto-appended based on connection type (389/636)
                </p>
              </div>

              {/* LDAPS toggle */}
              <div className="flex items-center justify-between rounded-lg border border-border bg-background p-3">
                <div className="flex items-center gap-2">
                  <Lock className={`h-4 w-4 ${useLdaps ? "text-success" : "text-muted-foreground"}`} />
                  <div>
                    <p className="text-sm font-medium text-foreground">Use LDAPS (Secure)</p>
                    <p className="text-xs text-muted-foreground">
                      {useLdaps ? "Port 636 - TLS encrypted" : "Port 389 - Unencrypted (not recommended)"}
                    </p>
                  </div>
                </div>
                <Button
                  type="button"
                  variant={useLdaps ? "default" : "outline"}
                  size="sm"
                  onClick={() => setUseLdaps(!useLdaps)}
                  className={useLdaps ? "bg-success hover:bg-success/90" : ""}
                >
                  {useLdaps ? "Enabled" : "Disabled"}
                </Button>
              </div>

              {!useLdaps && (
                <div className="flex items-start gap-2 rounded-lg bg-warning/10 p-3 text-sm">
                  <AlertTriangle className="mt-0.5 h-4 w-4 text-warning" />
                  <span className="text-warning">
                    Warning: Plain LDAP transmits credentials in clear text. Use LDAPS for production environments.
                  </span>
                </div>
              )}

              {/* Base DN input */}
              <div className="space-y-2">
                <Label htmlFor="cred-basedn" className="flex items-center justify-between text-foreground">
                  Base DN
                  <ValidationIcon valid={baseDnValid} />
                </Label>
                <Input
                  id="cred-basedn"
                  value={baseDn}
                  onChange={(e) => setBaseDn(e.target.value)}
                  placeholder="DC=company,DC=com"
                  className="bg-background"
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
            </>
          )}

          {/* Username input */}
          <div className="space-y-2">
            <Label htmlFor="cred-username" className="flex items-center justify-between text-foreground">
              Domain Admin Username
              <ValidationIcon valid={usernameValid} />
            </Label>
            <Input
              id="cred-username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="CN=admin,CN=Users,DC=company,DC=com"
              className="bg-background"
              autoComplete="off"
              spellCheck={false}
              readOnly={isReauthentication}
            />
            <p className="text-xs text-muted-foreground">Accepts DN, UPN (user@domain.com), or DOMAIN\\user format</p>
          </div>

          {/* Password input */}
          <div className="space-y-2">
            <Label htmlFor="cred-password" className="flex items-center gap-2 text-foreground">
              <KeyRound className="h-4 w-4" />
              Password
            </Label>
            <div className="relative">
              <Input
                id="cred-password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="bg-background pr-10"
                autoComplete="new-password"
                placeholder="Enter your password"
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? (
                  <EyeOff className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <Eye className="h-4 w-4 text-muted-foreground" />
                )}
              </Button>
            </div>

            {/* Password strength indicator */}
            {password && (
              <div className="space-y-1">
                <div className="flex gap-1">
                  {[1, 2, 3, 4, 5, 6].map((i) => (
                    <div
                      key={i}
                      className={`h-1 flex-1 rounded-full ${
                        i <= passwordStrength.score ? passwordStrength.color : "bg-muted"
                      }`}
                    />
                  ))}
                </div>
                <p className={`text-xs ${passwordStrength.color.replace("bg-", "text-")}`}>
                  Password strength: {passwordStrength.label}
                </p>
              </div>
            )}
          </div>

          {/* Error message */}
          {error && (
            <div className="flex items-start gap-2 rounded-lg bg-destructive/10 p-3 text-sm">
              <AlertTriangle className="mt-0.5 h-4 w-4 text-destructive" />
              <span className="text-destructive">{error}</span>
            </div>
          )}

          {/* Security tips */}
          <div className="rounded-lg border border-border bg-background p-3">
            <div className="flex items-center gap-2 text-sm font-medium text-foreground">
              <Info className="h-4 w-4 text-primary" />
              Security Tips
            </div>
            <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
              <li>• Use a dedicated service account with minimal privileges</li>
              <li>• Ensure account has "Disable User" permissions only</li>
              <li>• Session will timeout after 30 minutes of inactivity</li>
            </ul>
          </div>

          {/* Action buttons */}
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={loading}>
              Cancel
            </Button>
            <Button type="submit" disabled={loading || !password} className="bg-primary">
              {loading ? (
                <>
                  <div className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent" />
                  Authenticating...
                </>
              ) : (
                <>
                  <Shield className="mr-2 h-4 w-4" />
                  {isReauthentication ? "Confirm Identity" : "Connect Securely"}
                </>
              )}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
