/** Risk Scoring Dashboard -- aggregate security risk score with category breakdown and trend charts. */
"use client"

import { useState } from "react"
import { invoke } from "@/lib/tauri-api"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { AlertCircle, TrendingUp, TrendingDown, Minus, User, Server, Shield } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Progress } from "@/components/ui/progress"
import type { UserRiskScore, DomainRiskScore, RiskLevel } from "@/lib/advanced-features-types"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from "recharts"

interface RiskScoringDashboardProps {
  isConnected: boolean
}

export function RiskScoringDashboard({ isConnected }: RiskScoringDashboardProps) {
  const [userRisk, setUserRisk] = useState<UserRiskScore | null>(null)
  const [domainRisk, setDomainRisk] = useState<DomainRiskScore | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // User risk form
  const [username, setUsername] = useState("")
  const [userDn, setUserDn] = useState("")

  // Domain risk form
  const [domainName, setDomainName] = useState("")
  const [krbtgtAgeDays, setKrbtgtAgeDays] = useState("365")

  const getRiskLevelColor = (level: RiskLevel) => {
    switch (level) {
      case "Critical":
        return "bg-red-500 text-white"
      case "High":
        return "bg-orange-500 text-white"
      case "Medium":
        return "bg-yellow-500 text-black"
      case "Low":
        return "bg-green-500 text-white"
      default:
        return "bg-gray-500 text-white"
    }
  }

  const getRiskLevelColorHex = (level: RiskLevel) => {
    switch (level) {
      case "Critical":
        return "#ef4444"
      case "High":
        return "#f97316"
      case "Medium":
        return "#eab308"
      case "Low":
        return "#22c55e"
      default:
        return "#6b7280"
    }
  }

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case "Improving":
        return <TrendingDown className="h-4 w-4 text-green-500" />
      case "Degrading":
        return <TrendingUp className="h-4 w-4 text-red-500" />
      case "Stable":
        return <Minus className="h-4 w-4 text-gray-500" />
      default:
        return null
    }
  }

  const scoreUserRisk = async () => {
    if (!isConnected || !username) {
      setError("Please ensure AD is connected and username is provided")
      return
    }

    setLoading(true)
    setError(null)

    try {
      // Example data - in production, this would come from AD queries
      const result = await invoke<UserRiskScore>("score_user_risk", {
        userDn: userDn || `CN=${username},OU=Users,DC=example,DC=com`,
        username,
        isPrivileged: false,
        isEnabled: true,
        lastLogon: new Date().toISOString(),
        passwordLastSet: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString(),
        privilegedGroups: [],
        hasAdminRights: false,
        failedLogonCount: 2,
        servicePrincipalNames: [],
      })
      setUserRisk(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  const scoreDomainRisk = async () => {
    if (!isConnected || !domainName) {
      setError("Please ensure AD is connected and domain name is provided")
      return
    }

    setLoading(true)
    setError(null)

    try {
      const result = await invoke<DomainRiskScore>("score_domain_risk", {
        domainName,
        krbtgtAgeDays: parseInt(krbtgtAgeDays),
        adminCount: 50,
        staleAdminCount: 10,
        weakPasswordCount: 25,
        gpoIssuesCount: 5,
        delegationIssuesCount: 3,
        trustIssuesCount: 2,
        permissionIssuesCount: 4,
      })
      setDomainRisk(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Risk Scoring</h2>
          <p className="text-muted-foreground">Assess security risk levels for users and domains</p>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Tabs defaultValue="user" className="space-y-4">
        <TabsList>
          <TabsTrigger value="user">
            <User className="mr-2 h-4 w-4" />
            User Risk
          </TabsTrigger>
          <TabsTrigger value="domain">
            <Server className="mr-2 h-4 w-4" />
            Domain Risk
          </TabsTrigger>
        </TabsList>

        {/* User Risk Tab */}
        <TabsContent value="user" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Score User Risk</CardTitle>
              <CardDescription>Calculate comprehensive risk score for a user account</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Username</label>
                  <Input
                    placeholder="e.g., jdoe"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Distinguished Name (Optional)</label>
                  <Input
                    placeholder="e.g., CN=John Doe,OU=Users,DC=example,DC=com"
                    value={userDn}
                    onChange={(e) => setUserDn(e.target.value)}
                  />
                </div>
              </div>

              <Button onClick={scoreUserRisk} disabled={loading || !isConnected || !username} className="mt-4">
                <Shield className="mr-2 h-4 w-4" />
                Calculate Risk Score
              </Button>
            </CardContent>
          </Card>

          {userRisk && (
            <>
              <div className="grid gap-4 md:grid-cols-3">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">Overall Risk Score</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-bold">{userRisk.overall_score.toFixed(1)}</div>
                    <Badge className={`mt-2 ${getRiskLevelColor(userRisk.risk_level)}`}>
                      {userRisk.risk_level}
                    </Badge>
                    <Progress value={userRisk.overall_score} className="mt-2" />
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">User</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-xl font-bold">{userRisk.username}</div>
                    <div className="text-sm text-muted-foreground mt-1">{userRisk.user_dn}</div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">Risk Factors</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-bold">{userRisk.factors.length}</div>
                    <div className="text-sm text-muted-foreground mt-1">
                      {userRisk.factors.filter((f) => f.score > 50).length} High Risk
                    </div>
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle>Risk Factors Breakdown</CardTitle>
                  <CardDescription>Individual risk contributors and their impact</CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={userRisk.factors}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
                      <YAxis />
                      <Tooltip />
                      <Bar dataKey="score" fill="#3b82f6" />
                    </BarChart>
                  </ResponsiveContainer>

                  <div className="mt-6 space-y-4">
                    {userRisk.factors.map((factor, i) => (
                      <div key={i} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-semibold">{factor.name}</h4>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline">Weight: {(factor.weight * 100).toFixed(0)}%</Badge>
                            <Badge variant="outline">Score: {factor.score.toFixed(1)}</Badge>
                          </div>
                        </div>
                        <p className="text-sm text-muted-foreground mb-2">{factor.description}</p>
                        {factor.evidence.length > 0 && (
                          <div className="text-xs space-y-1 mb-2">
                            <div className="font-medium">Evidence:</div>
                            <ul className="list-disc list-inside">
                              {factor.evidence.map((ev, j) => (
                                <li key={j}>{ev}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                        <div className="text-xs">
                          <span className="font-medium">Mitigation:</span> {factor.mitigation}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Recommendations</CardTitle>
                  <CardDescription>Prioritized actions to reduce user risk</CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    {userRisk.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <Badge variant="outline" className="mt-0.5">
                          {i + 1}
                        </Badge>
                        <span className="text-sm">{rec}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>

        {/* Domain Risk Tab */}
        <TabsContent value="domain" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Score Domain Risk</CardTitle>
              <CardDescription>Calculate comprehensive risk score for a domain</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Domain Name</label>
                  <Input
                    placeholder="e.g., example.com"
                    value={domainName}
                    onChange={(e) => setDomainName(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">KRBTGT Age (Days)</label>
                  <Input
                    type="number"
                    placeholder="365"
                    value={krbtgtAgeDays}
                    onChange={(e) => setKrbtgtAgeDays(e.target.value)}
                  />
                </div>
              </div>

              <Button onClick={scoreDomainRisk} disabled={loading || !isConnected || !domainName} className="mt-4">
                <Shield className="mr-2 h-4 w-4" />
                Calculate Risk Score
              </Button>
            </CardContent>
          </Card>

          {domainRisk && (
            <>
              <div className="grid gap-4 md:grid-cols-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">Overall Risk Score</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-bold">{domainRisk.overall_score.toFixed(1)}</div>
                    <Badge className={`mt-2 ${getRiskLevelColor(domainRisk.risk_level)}`}>
                      {domainRisk.risk_level}
                    </Badge>
                    <Progress value={domainRisk.overall_score} className="mt-2" />
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">Domain</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-xl font-bold">{domainRisk.domain_name}</div>
                    <div className="text-sm text-muted-foreground mt-1">
                      {domainRisk.domain_id ? `ID: ${domainRisk.domain_id}` : "No ID"}
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">Trend</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center gap-2">
                      {getTrendIcon(domainRisk.trend)}
                      <span className="text-xl font-bold">{domainRisk.trend}</span>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">Top Risks</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-bold">{domainRisk.top_risks.length}</div>
                    <div className="text-sm text-muted-foreground mt-1">Critical issues</div>
                  </CardContent>
                </Card>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>Risk by Category</CardTitle>
                    <CardDescription>Security risk breakdown by category</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ResponsiveContainer width="100%" height={300}>
                      <PieChart>
                        <Pie
                          data={domainRisk.category_breakdown}
                          dataKey="score"
                          nameKey="category"
                          cx="50%"
                          cy="50%"
                          outerRadius={100}
                          label
                        >
                          {domainRisk.category_breakdown.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={getRiskLevelColorHex(entry.risk_level)} />
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
                    <CardTitle>Category Details</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[300px]">
                      <div className="space-y-3">
                        {domainRisk.category_breakdown.map((cat, i) => (
                          <div key={i} className="border rounded-lg p-3">
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-semibold">{cat.category}</span>
                              <Badge className={getRiskLevelColor(cat.risk_level)}>{cat.risk_level}</Badge>
                            </div>
                            <div className="flex items-center justify-between text-sm">
                              <span className="text-muted-foreground">Score:</span>
                              <span className="font-bold">{cat.score.toFixed(1)}</span>
                            </div>
                            <div className="flex items-center justify-between text-sm">
                              <span className="text-muted-foreground">Issues:</span>
                              <span className="font-bold">{cat.issue_count}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle>Top Risks</CardTitle>
                  <CardDescription>Most critical security concerns for this domain</CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    {domainRisk.top_risks.map((risk, i) => (
                      <li key={i} className="flex items-start gap-2 p-3 border rounded-lg">
                        <Badge variant="destructive" className="mt-0.5">
                          {i + 1}
                        </Badge>
                        <span className="text-sm flex-1">{risk}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Recommendations</CardTitle>
                  <CardDescription>Prioritized actions to improve domain security</CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    {domainRisk.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <Badge variant="outline" className="mt-0.5">
                          {i + 1}
                        </Badge>
                        <span className="text-sm">{rec}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}
