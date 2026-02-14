/** Incident Manager -- tracks security incidents with lifecycle management and action logging. */
"use client"

import type React from "react"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { createIncident, getIncidents, updateIncidentStatus, type Incident } from "@/lib/tauri-api"
import { Plus, AlertTriangle, Clock, CheckCircle } from "lucide-react"

export function IncidentManager() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null)
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)

  useEffect(() => {
    loadIncidents()
  }, [])

  const loadIncidents = async () => {
    try {
      const data = await getIncidents()
      setIncidents(data)
    } catch (error) {
      // Incident loading failure; loading state reset in finally block
    } finally {
      setLoading(false)
    }
  }

  const handleCreateIncident = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const formData = new FormData(e.currentTarget)

    try {
      await createIncident(
        formData.get("title") as string,
        formData.get("description") as string,
        formData.get("priority") as string,
        (formData.get("systems") as string).split(",").map((s) => s.trim()),
      )
      setIsCreateDialogOpen(false)
      loadIncidents()
    } catch (error) {
      // Incident creation failure; dialog remains open for retry
    }
  }

  const handleStatusChange = async (incidentId: string, status: string) => {
    try {
      await updateIncidentStatus(incidentId, status)
      loadIncidents()
    } catch (error) {
      // Status update failure; original status remains in UI
    }
  }

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case "Critical":
        return <AlertTriangle className="h-4 w-4 text-destructive" />
      case "High":
        return <Clock className="h-4 w-4 text-warning" />
      default:
        return <CheckCircle className="h-4 w-4 text-info" />
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Incident Management</h2>
          <p className="text-sm text-muted-foreground">Track and respond to security incidents</p>
        </div>
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button className="bg-primary text-primary-foreground">
              <Plus className="mr-2 h-4 w-4" />
              New Incident
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-card">
            <DialogHeader>
              <DialogTitle className="text-foreground">Create New Incident</DialogTitle>
              <DialogDescription className="text-muted-foreground">
                Document a new security incident for tracking and response
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handleCreateIncident} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="title" className="text-foreground">
                  Title
                </Label>
                <Input
                  id="title"
                  name="title"
                  placeholder="Unauthorized access attempt"
                  required
                  className="bg-background"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description" className="text-foreground">
                  Description
                </Label>
                <Textarea
                  id="description"
                  name="description"
                  placeholder="Detailed description of the incident..."
                  required
                  className="bg-background"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="priority" className="text-foreground">
                  Priority
                </Label>
                <Select name="priority" defaultValue="medium" required>
                  <SelectTrigger className="bg-background">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="systems" className="text-foreground">
                  Affected Systems
                </Label>
                <Input
                  id="systems"
                  name="systems"
                  placeholder="server1, database2, workstation3"
                  className="bg-background"
                />
              </div>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
                  Cancel
                </Button>
                <Button type="submit" className="bg-primary">
                  Create Incident
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-border border-t-primary" />
        </div>
      ) : incidents.length === 0 ? (
        <Card className="border-border bg-card">
          <CardContent className="flex flex-col items-center justify-center py-12">
            <AlertTriangle className="mb-4 h-12 w-12 text-muted-foreground" />
            <p className="text-lg font-medium text-foreground">No incidents found</p>
            <p className="text-sm text-muted-foreground">Create your first incident to get started</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4">
          {incidents.map((incident) => (
            <Card key={incident.id} className="border-border bg-card">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-3">
                    {getPriorityIcon(incident.priority)}
                    <div>
                      <CardTitle className="text-foreground">{incident.title}</CardTitle>
                      <p className="mt-1 text-sm text-muted-foreground">{incident.description}</p>
                    </div>
                  </div>
                  <Select
                    defaultValue={incident.status}
                    onValueChange={(value) => handleStatusChange(incident.id, value)}
                  >
                    <SelectTrigger className="w-[180px] bg-background">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Open">Open</SelectItem>
                      <SelectItem value="Investigating">Investigating</SelectItem>
                      <SelectItem value="Contained">Contained</SelectItem>
                      <SelectItem value="Resolved">Resolved</SelectItem>
                      <SelectItem value="Closed">Closed</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Priority: </span>
                      <span
                        className={`font-medium ${
                          incident.priority === "Critical"
                            ? "text-destructive"
                            : incident.priority === "High"
                              ? "text-warning"
                              : "text-info"
                        }`}
                      >
                        {incident.priority}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Created: </span>
                      <span className="font-medium text-foreground">
                        {new Date(incident.created_at).toLocaleString()}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Affected Systems: </span>
                      <span className="font-medium text-foreground">{incident.affected_systems.length}</span>
                    </div>
                  </div>
                  {incident.actions.length > 0 && (
                    <div className="border-t border-border pt-4">
                      <p className="mb-2 text-sm font-medium text-foreground">Recent Actions</p>
                      <div className="space-y-2">
                        {incident.actions.slice(-3).map((action) => (
                          <div key={action.id} className="rounded-lg bg-background p-2 text-sm">
                            <div className="flex items-center justify-between">
                              <span className="font-medium text-foreground">{action.action_type}</span>
                              <span className="text-xs text-muted-foreground">
                                {new Date(action.timestamp).toLocaleString()}
                              </span>
                            </div>
                            <p className="mt-1 text-muted-foreground">{action.description}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
