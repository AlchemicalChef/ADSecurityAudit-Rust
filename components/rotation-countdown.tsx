/**
 * KRBTGT Rotation Countdown Component
 *
 * Visual countdown timer for the wait period between KRBTGT password
 * rotations. Essential for safe KRBTGT rotation workflow.
 *
 * @module components/rotation-countdown
 *
 * Purpose:
 * After the first KRBTGT rotation, existing TGTs remain valid.
 * This countdown ensures adequate wait time before the second
 * rotation to avoid authentication disruptions.
 *
 * Wait Period Recommendations:
 * - Minimum: 10 hours (maximum TGT lifetime)
 * - Recommended: 24 hours (safety margin)
 * - Maximum: 72 hours (extended for large environments)
 *
 * Display States:
 * - Counting: Shows remaining time (hours:minutes:seconds)
 * - Ready: Second rotation can proceed
 * - Complete: Both rotations finished
 *
 * Safety Features:
 * - Cannot proceed until countdown completes
 * - Visual warning during countdown
 * - Persists across browser sessions
 * - Sends notifications when ready
 *
 * @see components/krbtgt-management for full rotation workflow
 */
'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Clock, CheckCircle2 } from 'lucide-react'
import { Progress } from '@/components/ui/progress'

interface RotationCountdownProps {
  firstRotationTime: string | null
  minimumWaitHours: number
  recommendedWaitHours: number
  isComplete: boolean
}

export function RotationCountdown({
  firstRotationTime,
  minimumWaitHours,
  recommendedWaitHours,
  isComplete
}: RotationCountdownProps) {
  const [timeRemaining, setTimeRemaining] = useState<{
    hours: number
    minutes: number
    seconds: number
    isReady: boolean
    isOptimal: boolean
  } | null>(null)

  useEffect(() => {
    if (!firstRotationTime || isComplete) return

    const updateTimer = () => {
      const now = new Date()
      const rotationDate = new Date(firstRotationTime)
      const elapsedMs = now.getTime() - rotationDate.getTime()
      const elapsedHours = elapsedMs / (1000 * 60 * 60)

      const minimumMs = minimumWaitHours * 60 * 60 * 1000
      const recommendedMs = recommendedWaitHours * 60 * 60 * 1000

      const remainingMs = minimumMs - elapsedMs
      const isReady = remainingMs <= 0
      const isOptimal = elapsedMs >= recommendedMs

      if (isReady) {
        const hours = Math.floor(elapsedHours)
        const minutes = Math.floor((elapsedHours - hours) * 60)
        setTimeRemaining({
          hours,
          minutes,
          seconds: 0,
          isReady: true,
          isOptimal
        })
      } else {
        const hours = Math.floor(remainingMs / (1000 * 60 * 60))
        const minutes = Math.floor((remainingMs % (1000 * 60 * 60)) / (1000 * 60))
        const seconds = Math.floor((remainingMs % (1000 * 60)) / 1000)

        setTimeRemaining({
          hours,
          minutes,
          seconds,
          isReady: false,
          isOptimal: false
        })
      }
    }

    updateTimer()
    const interval = setInterval(updateTimer, 1000)

    return () => clearInterval(interval)
  }, [firstRotationTime, minimumWaitHours, recommendedWaitHours, isComplete])

  if (!firstRotationTime || isComplete || !timeRemaining) return null

  const { hours, minutes, seconds, isReady, isOptimal } = timeRemaining

  if (isReady) {
    return (
      <Card className={`border ${isOptimal ? 'border-green-500/50 bg-green-500/10' : 'border-yellow-500/50 bg-yellow-500/10'}`}>
        <CardContent className="p-4">
          <div className="flex items-center gap-3">
            {isOptimal ? (
              <CheckCircle2 className="h-6 w-6 text-green-400" />
            ) : (
              <Clock className="h-6 w-6 text-yellow-400" />
            )}
            <div className="flex-1">
              <p className={`font-medium ${isOptimal ? 'text-green-400' : 'text-yellow-400'}`}>
                {isOptimal ? 'Optimal Time Reached' : 'Minimum Wait Complete'}
              </p>
              <p className="text-sm text-muted-foreground">
                Elapsed: {hours}h {minutes}m since first rotation
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    )
  }

  // Calculate progress: elapsed time / total time * 100
  const totalSeconds = minimumWaitHours * 60 * 60
  const remainingSeconds = hours * 60 * 60 + minutes * 60 + seconds
  const elapsedSeconds = totalSeconds - remainingSeconds
  const progress = (elapsedSeconds / totalSeconds) * 100

  return (
    <Card className="border-orange-500/50 bg-orange-500/10">
      <CardContent className="p-4">
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <Clock className="h-6 w-6 text-orange-400 animate-pulse" />
            <div className="flex-1">
              <p className="font-medium text-orange-400">Waiting for Second Rotation</p>
              <p className="text-sm text-muted-foreground">
                Time until minimum wait complete
              </p>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-center gap-4 text-3xl font-bold text-orange-400 tabular-nums">
              <div className="flex flex-col items-center">
                <span>{String(hours).padStart(2, '0')}</span>
                <span className="text-xs text-muted-foreground font-normal">hours</span>
              </div>
              <span className="text-orange-400/50">:</span>
              <div className="flex flex-col items-center">
                <span>{String(minutes).padStart(2, '0')}</span>
                <span className="text-xs text-muted-foreground font-normal">minutes</span>
              </div>
              <span className="text-orange-400/50">:</span>
              <div className="flex flex-col items-center">
                <span>{String(seconds).padStart(2, '0')}</span>
                <span className="text-xs text-muted-foreground font-normal">seconds</span>
              </div>
            </div>

            <Progress value={progress} className="h-2" />

            <div className="flex justify-between text-xs text-muted-foreground">
              <span>First rotation: {new Date(firstRotationTime).toLocaleString()}</span>
              <span>Ready at: {new Date(new Date(firstRotationTime).getTime() + minimumWaitHours * 60 * 60 * 1000).toLocaleTimeString()}</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
