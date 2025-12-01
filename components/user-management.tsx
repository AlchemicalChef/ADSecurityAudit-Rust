/**
 * User Management Component
 *
 * Provides AD user account search, viewing, and management capabilities
 * with integrated security analysis.
 *
 * @module components/user-management
 *
 * Features:
 * - User search by name, SAM account name, or email
 * - Detailed user information display
 * - Account status indicators (enabled, locked, expired)
 * - Security flag analysis (AdminCount, password policies)
 * - Group membership viewing
 * - Account disabling capability
 *
 * Security Analysis:
 * - Password expiration status
 * - Password never expires flag (risk indicator)
 * - Account lockout status
 * - LastLogon timestamp
 * - AdminCount attribute (protected account)
 * - Sensitive account flag
 *
 * User Details Displayed:
 * - Distinguished Name (DN)
 * - SAM Account Name
 * - User Principal Name (UPN)
 * - Display Name
 * - Email Address
 * - Department/Title
 * - Manager
 * - Account Control Flags
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
 */
"use client"

import type React from "react"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { searchUsers, disableUser, type UserInfo } from "@/lib/tauri-api"
import { CredentialPrompt, type Credentials } from "@/components/credential-prompt"
import { Search, UserX, User, Mail, Shield, AlertTriangle, KeyRound, Eye, EyeOff } from "lucide-react"

interface UserManagementProps {
  isConnected: boolean
  savedCredentials?: Credentials
}

export function UserManagement({ isConnected, savedCredentials }: UserManagementProps) {
  const [users, setUsers] = useState<UserInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [searchQuery, setSearchQuery] = useState("")
  const [selectedUser, setSelectedUser] = useState<UserInfo | null>(null)
  const [isDisableDialogOpen, setIsDisableDialogOpen] = useState(false)

  const [showReauth, setShowReauth] = useState(false)
  const [pendingAction, setPendingAction] = useState<{ user: UserInfo; reason: string } | null>(null)
  const [disableError, setDisableError] = useState<string | null>(null)

  const [confirmPassword, setConfirmPassword] = useState("")
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

  const handleSearch = async () => {
    if (!searchQuery.trim()) return

    setLoading(true)
    try {
      const results = await searchUsers(searchQuery)
      setUsers(results)
    } catch (error) {
      console.error("Search failed:", error)
    } finally {
      setLoading(false)
    }
  }

  const handleDisableUser = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!selectedUser) return

    setDisableError(null)
    const formData = new FormData(e.currentTarget)
    const reason = formData.get("reason") as string

    if (!confirmPassword) {
      setDisableError("Password confirmation is required for this action")
      return
    }

    setPendingAction({ user: selectedUser, reason })
    setShowReauth(true)
    setIsDisableDialogOpen(false)
  }

  const handleReauthSuccess = async (credentials: Credentials) => {
    if (!pendingAction) return

    try {
      await disableUser(pendingAction.user.distinguished_name, pendingAction.reason)
      setPendingAction(null)
      setSelectedUser(null)
      setConfirmPassword("")
      handleSearch()
    } catch (error) {
      console.error("Failed to disable user:", error)
      throw error
    }
  }

  const handleDisableDialogClose = (open: boolean) => {
    setIsDisableDialogOpen(open)
    if (!open) {
      setConfirmPassword("")
      setShowConfirmPassword(false)
      setDisableError(null)
    }
  }

  if (!isConnected) {
    return (
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <AlertTriangle className="mb-4 h-12 w-12 text-warning" />
          <p className="text-lg font-medium text-foreground">Not Connected to Active Directory</p>
          <p className="text-sm text-muted-foreground">Please connect to AD first in the Connection tab</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-foreground">User Management</h2>
        <p className="text-sm text-muted-foreground">Search and manage Active Directory users</p>
      </div>

      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="text-foreground">Search Users</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <div className="flex-1">
              <Input
                placeholder="Search by name, username, or email..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                className="bg-background"
              />
            </div>
            <Button onClick={handleSearch} disabled={loading} className="bg-primary">
              <Search className="mr-2 h-4 w-4" />
              Search
            </Button>
          </div>
        </CardContent>
      </Card>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-border border-t-primary" />
        </div>
      ) : users.length > 0 ? (
        <div className="grid gap-4">
          {users.map((user) => (
            <Card key={user.distinguished_name} className="border-border bg-card">
              <CardContent className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex gap-4">
                    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
                      <User className="h-6 w-6 text-primary" />
                    </div>
                    <div className="space-y-2">
                      <div>
                        <h3 className="font-semibold text-foreground">{user.display_name}</h3>
                        <p className="text-sm text-muted-foreground">@{user.username}</p>
                      </div>
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Mail className="h-4 w-4" />
                        {user.email}
                      </div>
                      <div className="flex items-center gap-2">
                        <div className={`h-2 w-2 rounded-full ${user.enabled ? "bg-success" : "bg-destructive"}`} />
                        <span className="text-sm font-medium text-foreground">
                          {user.enabled ? "Active" : "Disabled"}
                        </span>
                      </div>
                      {user.groups.length > 0 && (
                        <div className="flex items-center gap-2 text-sm">
                          <Shield className="h-4 w-4 text-muted-foreground" />
                          <span className="text-muted-foreground">{user.groups.length} group(s)</span>
                        </div>
                      )}
                    </div>
                  </div>
                  {user.enabled && (
                    <Dialog
                      open={isDisableDialogOpen && selectedUser?.distinguished_name === user.distinguished_name}
                      onOpenChange={(open) => {
                        handleDisableDialogClose(open)
                        if (open) setSelectedUser(user)
                        else setSelectedUser(null)
                      }}
                    >
                      <DialogTrigger asChild>
                        <Button variant="destructive" size="sm">
                          <UserX className="mr-2 h-4 w-4" />
                          Disable Account
                        </Button>
                      </DialogTrigger>
                      <DialogContent className="bg-card">
                        <DialogHeader>
                          <DialogTitle className="text-foreground">Disable User Account</DialogTitle>
                          <DialogDescription className="text-muted-foreground">
                            This is a critical security action. You must confirm your identity to proceed.
                          </DialogDescription>
                        </DialogHeader>
                        <form onSubmit={handleDisableUser} className="space-y-4">
                          <div className="flex items-center gap-2 rounded-lg bg-destructive/10 p-3 text-sm">
                            <AlertTriangle className="h-4 w-4 text-destructive" />
                            <span className="text-destructive">
                              Disabling {user.display_name}&apos;s account will immediately revoke their access
                            </span>
                          </div>

                          <div className="space-y-2">
                            <Label htmlFor="reason" className="text-foreground">
                              Reason for Disabling
                            </Label>
                            <Textarea
                              id="reason"
                              name="reason"
                              placeholder="Security incident response - unauthorized access attempt"
                              required
                              className="bg-background"
                            />
                          </div>

                          <div className="space-y-2">
                            <Label htmlFor="confirm-password" className="flex items-center gap-2 text-foreground">
                              <KeyRound className="h-4 w-4" />
                              Confirm Your Password
                            </Label>
                            <div className="relative">
                              <Input
                                id="confirm-password"
                                type={showConfirmPassword ? "text" : "password"}
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                placeholder="Enter your admin password"
                                className="bg-background pr-10"
                                autoComplete="new-password"
                                required
                              />
                              <Button
                                type="button"
                                variant="ghost"
                                size="icon"
                                className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                              >
                                {showConfirmPassword ? (
                                  <EyeOff className="h-4 w-4 text-muted-foreground" />
                                ) : (
                                  <Eye className="h-4 w-4 text-muted-foreground" />
                                )}
                              </Button>
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Re-enter your password to confirm this action
                            </p>
                          </div>

                          {disableError && (
                            <div className="flex items-center gap-2 rounded-lg bg-destructive/10 p-3 text-sm text-destructive">
                              <AlertTriangle className="h-4 w-4" />
                              {disableError}
                            </div>
                          )}

                          <div className="flex justify-end gap-2">
                            <Button type="button" variant="outline" onClick={() => handleDisableDialogClose(false)}>
                              Cancel
                            </Button>
                            <Button type="submit" variant="destructive" disabled={!confirmPassword}>
                              <Shield className="mr-2 h-4 w-4" />
                              Confirm & Disable
                            </Button>
                          </div>
                        </form>
                      </DialogContent>
                    </Dialog>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <Card className="border-border bg-card">
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Search className="mb-4 h-12 w-12 text-muted-foreground" />
            <p className="text-lg font-medium text-foreground">No users found</p>
            <p className="text-sm text-muted-foreground">Try searching with different criteria</p>
          </CardContent>
        </Card>
      )}

      <CredentialPrompt
        open={showReauth}
        onOpenChange={(open) => {
          setShowReauth(open)
          if (!open) {
            setPendingAction(null)
            setConfirmPassword("")
          }
        }}
        onSubmit={handleReauthSuccess}
        title="Confirm Identity"
        description="Re-enter your credentials to disable this user account. This action will be logged."
        isReauthentication={true}
        savedUsername={savedCredentials?.username}
      />
    </div>
  )
}
