"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Checkbox } from "@/components/ui/checkbox"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Progress } from "@/components/ui/progress"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Key,
  AlertTriangle,
  CheckCircle2,
  Clock,
  RefreshCw,
  Shield,
  Info,
  AlertCircle,
  Calendar,
  Loader2,
  RotateCcw,
  ChevronRight,
} from "lucide-react"
import {
  analyzeKrbtgt,
  getKrbtgtRotationStatus,
  rotateKrbtgt,
  resetKrbtgtRotationStatus,
  type KrbtgtAgeAnalysis,
  type RotationStatus,
  type RotationResult,
  type KrbtgtRiskLevel,
} from "@/lib/tauri-api"
import { RotationCountdown } from "@/components/rotation-countdown"

interface KrbtgtManagementProps {
  isConnected: boolean
}

export function KrbtgtManagement({ isConnected }: KrbtgtManagementProps) {
  const [analysis, setAnalysis] = useState<KrbtgtAgeAnalysis | null>(null)
  const [rotationStatus, setRotationStatus] = useState<RotationStatus | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [isRotating, setIsRotating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showRotationDialog, setShowRotationDialog] = useState(false)
  const [rotationNumber, setRotationNumber] = useState<1 | 2>(1)
  const [rotationReason, setRotationReason] = useState("")
  const [confirmUnderstanding, setConfirmUnderstanding] = useState(false)
  const [lastRotationResult, setLastRotationResult] = useState<RotationResult | null>(null)

  const loadData = async () => {
    if (!isConnected) return

    setIsLoading(true)
    setError(null)

    try {
      const [analysisData, statusData] = await Promise.all([analyzeKrbtgt(), getKrbtgtRotationStatus()])

      setAnalysis(analysisData)
      setRotationStatus(statusData)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load KRBTGT data")
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [isConnected])

  const getRiskColor = (level: KrbtgtRiskLevel) => {
    switch (level) {
      case "Critical":
        return "bg-red-500/20 text-red-400 border-red-500/50"
      case "High":
        return "bg-orange-500/20 text-orange-400 border-orange-500/50"
      case "Medium":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/50"
      case "Low":
        return "bg-blue-500/20 text-blue-400 border-blue-500/50"
      case "Healthy":
        return "bg-green-500/20 text-green-400 border-green-500/50"
      default:
        return "bg-muted text-muted-foreground"
    }
  }

  const getRiskIcon = (level: KrbtgtRiskLevel) => {
    switch (level) {
      case "Critical":
      case "High":
        return <AlertTriangle className="h-5 w-5" />
      case "Medium":
        return <AlertCircle className="h-5 w-5" />
      case "Low":
        return <Info className="h-5 w-5" />
      case "Healthy":
        return <CheckCircle2 className="h-5 w-5" />
    }
  }

  const handleStartRotation = (number: 1 | 2) => {
    setRotationNumber(number)
    setRotationReason("")
    setConfirmUnderstanding(false)
    setShowRotationDialog(true)
  }

  const handleRotate = async () => {
    if (!confirmUnderstanding || !rotationReason.trim()) return

    setIsRotating(true)
    try {
      const result = await rotateKrbtgt(rotationNumber, confirmUnderstanding, rotationReason)
      setLastRotationResult(result)
      setShowRotationDialog(false)
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to rotate KRBTGT")
    } finally {
      setIsRotating(false)
    }
  }

  const handleResetRotationCycle = async () => {
    try {
      await resetKrbtgtRotationStatus()
      setLastRotationResult(null)
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reset rotation status")
    }
  }

  const calculateAgeProgress = () => {
    if (!analysis) return 0
    const maxAge = analysis.recommended_max_age_days * 1.5
    return Math.min((analysis.age_days / maxAge) * 100, 100)
  }

  if (!isConnected) {
    return (
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <Key className="mb-4 h-12 w-12 text-muted-foreground" />
          <h3 className="mb-2 text-lg font-medium text-foreground">AD Connection Required</h3>
          <p className="text-center text-muted-foreground">
            Connect to Active Directory to analyze and manage the KRBTGT account.
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">KRBTGT Account Management</h2>
          <p className="text-muted-foreground">Monitor and rotate the Kerberos Ticket Granting Ticket account</p>
        </div>
        <Button onClick={loadData} disabled={isLoading} variant="outline">
          <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Educational Alert */}
      <Alert className="border-primary/50 bg-primary/10">
        <Info className="h-4 w-4 text-primary" />
        <AlertTitle className="text-primary">Why Two Rotations?</AlertTitle>
        <AlertDescription className="text-muted-foreground">
          The KRBTGT account is used to encrypt all Kerberos tickets in Active Directory. When rotated, AD keeps the
          previous password to decrypt existing tickets. To fully invalidate all tickets (including potential Golden
          Tickets), you must rotate <strong>twice</strong>:
          <ol className="mt-2 ml-4 list-decimal space-y-1">
            <li>First rotation invalidates tickets encrypted with the oldest key</li>
            <li>Wait for maximum TGT lifetime (default 10 hours) to let existing tickets expire</li>
            <li>Second rotation removes the old key entirely, invalidating any remaining tickets</li>
          </ol>
        </AlertDescription>
      </Alert>

      {isLoading && !analysis ? (
        <Card className="border-border bg-card">
          <CardContent className="flex items-center justify-center py-12">
            <Loader2 className="mr-2 h-6 w-6 animate-spin text-primary" />
            <span className="text-muted-foreground">Analyzing KRBTGT account...</span>
          </CardContent>
        </Card>
      ) : analysis ? (
        <>
          {/* Account Status Cards */}
          <div className="grid gap-4 md:grid-cols-4">
            <Card className="border-border bg-card">
              <CardContent className="pt-6">
                <div className="flex items-center gap-3">
                  <div className={`rounded-lg p-2 ${getRiskColor(analysis.risk_level)}`}>
                    {getRiskIcon(analysis.risk_level)}
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Risk Level</p>
                    <p className="text-xl font-bold text-foreground">{analysis.risk_level}</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border bg-card">
              <CardContent className="pt-6">
                <div className="flex items-center gap-3">
                  <div className="rounded-lg bg-muted p-2">
                    <Calendar className="h-5 w-5 text-muted-foreground" />
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Password Age</p>
                    <p className="text-xl font-bold text-foreground">{analysis.age_days} days</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border bg-card">
              <CardContent className="pt-6">
                <div className="flex items-center gap-3">
                  <div className="rounded-lg bg-muted p-2">
                    <Key className="h-5 w-5 text-muted-foreground" />
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Key Version</p>
                    <p className="text-xl font-bold text-foreground">{analysis.account_info.key_version_number}</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border bg-card">
              <CardContent className="pt-6">
                <div className="flex items-center gap-3">
                  <div className="rounded-lg bg-muted p-2">
                    <Shield className="h-5 w-5 text-muted-foreground" />
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Domain</p>
                    <p className="text-xl font-bold text-foreground truncate">{analysis.account_info.domain}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Age Progress */}
          <Card className="border-border bg-card">
            <CardHeader>
              <CardTitle className="text-foreground">Password Age Analysis</CardTitle>
              <CardDescription>Recommended maximum age: {analysis.recommended_max_age_days} days</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Current Age: {analysis.age_days} days</span>
                  <span className="text-muted-foreground">
                    {analysis.is_overdue
                      ? `${analysis.age_days - analysis.recommended_max_age_days} days overdue`
                      : `${analysis.recommended_max_age_days - analysis.age_days} days remaining`}
                  </span>
                </div>
                <Progress
                  value={calculateAgeProgress()}
                  className={`h-3 ${analysis.is_overdue ? "[&>div]:bg-destructive" : "[&>div]:bg-primary"}`}
                />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>0 days</span>
                  <span>{analysis.recommended_max_age_days} days (recommended)</span>
                  <span>{Math.round(analysis.recommended_max_age_days * 1.5)} days</span>
                </div>
              </div>

              <div className="grid gap-2 text-sm md:grid-cols-2">
                <div className="flex justify-between rounded-lg bg-muted/50 px-3 py-2">
                  <span className="text-muted-foreground">Last Changed</span>
                  <span className="font-medium text-foreground">
                    {new Date(analysis.account_info.last_password_change).toLocaleDateString()}
                  </span>
                </div>
                <div className="flex justify-between rounded-lg bg-muted/50 px-3 py-2">
                  <span className="text-muted-foreground">Account Created</span>
                  <span className="font-medium text-foreground">
                    {new Date(analysis.account_info.created).toLocaleDateString()}
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Rotation Status & Controls */}
          <Card className="border-border bg-card">
            <CardHeader>
              <CardTitle className="text-foreground">Rotation Management</CardTitle>
              <CardDescription>Manage KRBTGT password rotation cycle</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Rotation Progress Steps */}
              <div className="flex items-center gap-2">
                {/* Step 1 */}
                <div
                  className={`flex items-center gap-2 rounded-lg border px-4 py-3 ${
                    rotationStatus?.first_rotation_complete
                      ? "border-green-500/50 bg-green-500/10"
                      : "border-border bg-muted/50"
                  }`}
                >
                  {rotationStatus?.first_rotation_complete ? (
                    <CheckCircle2 className="h-5 w-5 text-green-400" />
                  ) : (
                    <div className="flex h-5 w-5 items-center justify-center rounded-full border-2 border-muted-foreground text-xs font-bold text-muted-foreground">
                      1
                    </div>
                  )}
                  <div>
                    <p className="font-medium text-foreground">First Rotation</p>
                    {rotationStatus?.first_rotation_time && (
                      <p className="text-xs text-muted-foreground">
                        {new Date(rotationStatus.first_rotation_time).toLocaleString()}
                      </p>
                    )}
                  </div>
                </div>

                <ChevronRight className="h-5 w-5 text-muted-foreground" />

                {/* Wait Period */}
                <div
                  className={`flex items-center gap-2 rounded-lg border px-4 py-3 ${
                    rotationStatus?.rotation_in_progress && !rotationStatus?.ready_for_second_rotation
                      ? "border-yellow-500/50 bg-yellow-500/10"
                      : rotationStatus?.ready_for_second_rotation
                        ? "border-green-500/50 bg-green-500/10"
                        : "border-border bg-muted/50"
                  }`}
                >
                  <Clock
                    className={`h-5 w-5 ${
                      rotationStatus?.rotation_in_progress && !rotationStatus?.ready_for_second_rotation
                        ? "text-yellow-400"
                        : rotationStatus?.ready_for_second_rotation
                          ? "text-green-400"
                          : "text-muted-foreground"
                    }`}
                  />
                  <div>
                    <p className="font-medium text-foreground">Wait Period</p>
                    <p className="text-xs text-muted-foreground">
                      {rotationStatus?.time_since_first_rotation !== undefined
                        ? `${rotationStatus.time_since_first_rotation}h elapsed`
                        : "10-24 hours"}
                    </p>
                  </div>
                </div>

                <ChevronRight className="h-5 w-5 text-muted-foreground" />

                {/* Step 2 */}
                <div
                  className={`flex items-center gap-2 rounded-lg border px-4 py-3 ${
                    rotationStatus?.second_rotation_complete
                      ? "border-green-500/50 bg-green-500/10"
                      : "border-border bg-muted/50"
                  }`}
                >
                  {rotationStatus?.second_rotation_complete ? (
                    <CheckCircle2 className="h-5 w-5 text-green-400" />
                  ) : (
                    <div className="flex h-5 w-5 items-center justify-center rounded-full border-2 border-muted-foreground text-xs font-bold text-muted-foreground">
                      2
                    </div>
                  )}
                  <div>
                    <p className="font-medium text-foreground">Second Rotation</p>
                    {rotationStatus?.second_rotation_time && (
                      <p className="text-xs text-muted-foreground">
                        {new Date(rotationStatus.second_rotation_time).toLocaleString()}
                      </p>
                    )}
                  </div>
                </div>
              </div>

              {/* Countdown Timer */}
              <RotationCountdown
                firstRotationTime={rotationStatus?.first_rotation_time || null}
                minimumWaitHours={rotationStatus?.minimum_wait_hours || 10}
                recommendedWaitHours={rotationStatus?.recommended_wait_hours || 24}
                isComplete={rotationStatus?.second_rotation_complete || false}
              />

              {/* Rotation Actions */}
              <div className="flex flex-wrap gap-3">
                {!rotationStatus?.first_rotation_complete && (
                  <Button onClick={() => handleStartRotation(1)} variant="destructive">
                    <RotateCcw className="mr-2 h-4 w-4" />
                    Start First Rotation
                  </Button>
                )}

                {rotationStatus?.first_rotation_complete && !rotationStatus?.second_rotation_complete && (
                  <Button
                    onClick={() => handleStartRotation(2)}
                    disabled={!rotationStatus.ready_for_second_rotation}
                    variant="destructive"
                  >
                    <RotateCcw className="mr-2 h-4 w-4" />
                    {rotationStatus.ready_for_second_rotation
                      ? "Complete Second Rotation"
                      : `Wait ${rotationStatus.minimum_wait_hours - (rotationStatus.time_since_first_rotation || 0)}h`}
                  </Button>
                )}

                {rotationStatus?.second_rotation_complete && (
                  <Button onClick={handleResetRotationCycle} variant="outline">
                    <RefreshCw className="mr-2 h-4 w-4" />
                    Start New Rotation Cycle
                  </Button>
                )}
              </div>

              {/* Last Rotation Result */}
              {lastRotationResult && (
                <Alert className="border-green-500/50 bg-green-500/10">
                  <CheckCircle2 className="h-4 w-4 text-green-400" />
                  <AlertTitle className="text-green-400">{lastRotationResult.message}</AlertTitle>
                  <AlertDescription className="text-muted-foreground">
                    <p className="mb-2">New Key Version: {lastRotationResult.new_key_version}</p>
                    <ul className="list-disc ml-4 space-y-1">
                      {lastRotationResult.next_steps.map((step, idx) => (
                        <li key={idx}>{step}</li>
                      ))}
                    </ul>
                  </AlertDescription>
                </Alert>
              )}
            </CardContent>
          </Card>

          {/* Recommendations */}
          <Card className="border-border bg-card">
            <CardHeader>
              <CardTitle className="text-foreground">Recommendations</CardTitle>
              <CardDescription>Actions based on current KRBTGT status</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {analysis.recommendations.map((rec, idx) => (
                <div key={idx} className={`rounded-lg border p-4 ${getRiskColor(rec.priority)}`}>
                  <div className="flex items-start gap-3">
                    {getRiskIcon(rec.priority)}
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <h4 className="font-medium">{rec.title}</h4>
                        {rec.action_required && (
                          <Badge variant="outline" className="text-xs">
                            Action Required
                          </Badge>
                        )}
                      </div>
                      <p className="mt-1 text-sm opacity-90">{rec.description}</p>
                    </div>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </>
      ) : null}

      {/* Rotation Confirmation Dialog */}
      <Dialog open={showRotationDialog} onOpenChange={setShowRotationDialog}>
        <DialogContent className="border-border bg-card sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-foreground">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Confirm KRBTGT Rotation {rotationNumber}
            </DialogTitle>
            <DialogDescription>
              {rotationNumber === 1
                ? "You are about to perform the first KRBTGT rotation. This is a critical security operation."
                : "You are about to complete the second rotation. This will invalidate ALL existing Kerberos tickets."}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Warning</AlertTitle>
              <AlertDescription>
                {rotationNumber === 1 ? (
                  <>
                    After this rotation, you MUST wait at least 10 hours before the second rotation. Performing both
                    rotations too quickly can cause widespread authentication failures.
                  </>
                ) : (
                  <>
                    This second rotation will immediately invalidate any Golden Tickets and all TGTs encrypted with the
                    previous key. Some users may need to re-authenticate.
                  </>
                )}
              </AlertDescription>
            </Alert>

            <div className="space-y-2">
              <Label htmlFor="rotation-reason" className="text-foreground">
                Reason for Rotation
              </Label>
              <Input
                id="rotation-reason"
                value={rotationReason}
                onChange={(e) => setRotationReason(e.target.value)}
                placeholder="e.g., Scheduled maintenance, Security incident response..."
                className="bg-background"
              />
            </div>

            <div className="flex items-start gap-2">
              <Checkbox
                id="confirm-understanding"
                checked={confirmUnderstanding}
                onCheckedChange={(checked) => setConfirmUnderstanding(checked === true)}
              />
              <Label htmlFor="confirm-understanding" className="text-sm text-muted-foreground leading-tight">
                I understand the implications of KRBTGT rotation and confirm this action is authorized and necessary.
                {rotationNumber === 1 && " I will wait at least 10 hours before performing the second rotation."}
              </Label>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRotationDialog(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleRotate}
              disabled={!confirmUnderstanding || !rotationReason.trim() || isRotating}
            >
              {isRotating ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Rotating...
                </>
              ) : (
                <>
                  <RotateCcw className="mr-2 h-4 w-4" />
                  Confirm Rotation {rotationNumber}
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
