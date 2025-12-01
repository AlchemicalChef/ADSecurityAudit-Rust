/**
 * Audit Report Export Dialog Component
 *
 * Provides export functionality for security audit results in multiple
 * formats suitable for compliance reporting and documentation.
 *
 * @module components/export-dialog
 *
 * Export Formats:
 * - JSON: Machine-readable, full data fidelity
 * - CSV: Spreadsheet-compatible, flat structure
 * - HTML: Self-contained report with styling
 * - PDF: Print-ready compliance documentation
 *
 * Export Content Options:
 * - Executive Summary: High-level risk overview
 * - Full Audit Report: Complete findings with details
 * - Findings Only: Security issues without context
 * - Recommendations: Remediation guidance
 *
 * Filtering Options:
 * - By severity level (Critical, High, Medium, Low)
 * - By audit category (Privileged Access, Delegation, etc.)
 * - By date range
 * - By affected object type
 *
 * Report Sections:
 * - Domain information and scan metadata
 * - Risk score summary
 * - Categorized findings with evidence
 * - Remediation recommendations
 * - Appendix with raw data
 */
'use client'

import { useState } from 'react'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Download, FileText, FileJson, Table, Loader2 } from 'lucide-react'
import { ExportFormat, ExportColumn, exportData } from '@/lib/export-utils'

// Re-export for convenience
export type { ExportColumn, ExportFormat }

interface ExportDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  data: any[]
  columns: ExportColumn[]
  title: string
  defaultFilename: string
  metadata?: {
    domain: string
    generatedBy: string
  }
}

export function ExportDialog({
  open,
  onOpenChange,
  data,
  columns,
  title,
  defaultFilename,
  metadata
}: ExportDialogProps) {
  const [format, setFormat] = useState<ExportFormat>('pdf')
  const [filename, setFilename] = useState(defaultFilename)
  const [includeTimestamp, setIncludeTimestamp] = useState(true)
  const [includeMetadata, setIncludeMetadata] = useState(true)
  const [isExporting, setIsExporting] = useState(false)

  const formatIcons = {
    pdf: <FileText className="h-4 w-4" />,
    csv: <Table className="h-4 w-4" />,
    json: <FileJson className="h-4 w-4" />
  }

  const formatDescriptions = {
    pdf: 'Formatted report with tables and styling (best for sharing)',
    csv: 'Spreadsheet format (best for Excel/data analysis)',
    json: 'Raw data format (best for automation/import)'
  }

  const handleExport = async () => {
    setIsExporting(true)
    try {
      await exportData(data, columns, {
        format,
        filename,
        title,
        includeTimestamp,
        includeMetadata
      }, includeMetadata ? {
        generatedAt: new Date().toISOString(),
        generatedBy: metadata?.generatedBy || 'IRP Tool',
        domain: metadata?.domain || 'Unknown',
        recordCount: data.length
      } : undefined)

      onOpenChange(false)
    } catch (error) {
      console.error('Export failed:', error)
    } finally {
      setIsExporting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Export {title}</DialogTitle>
          <DialogDescription>
            Export {data.length} records in your preferred format
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Format Selection */}
          <div className="space-y-2">
            <Label>Export Format</Label>
            <RadioGroup value={format} onValueChange={(v) => setFormat(v as ExportFormat)}>
              {(['pdf', 'csv', 'json'] as ExportFormat[]).map((fmt) => (
                <div key={fmt} className="flex items-center space-x-2 rounded-lg border border-border p-3 hover:bg-muted/50">
                  <RadioGroupItem value={fmt} id={fmt} />
                  <Label htmlFor={fmt} className="flex flex-1 cursor-pointer items-center gap-2">
                    {formatIcons[fmt]}
                    <div className="flex-1">
                      <div className="font-medium">{fmt.toUpperCase()}</div>
                      <div className="text-xs text-muted-foreground">
                        {formatDescriptions[fmt]}
                      </div>
                    </div>
                  </Label>
                </div>
              ))}
            </RadioGroup>
          </div>

          {/* Filename */}
          <div className="space-y-2">
            <Label htmlFor="filename">Filename</Label>
            <Input
              id="filename"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              placeholder="audit-report"
            />
            <p className="text-xs text-muted-foreground">
              Extension .{format} will be added automatically
            </p>
          </div>

          {/* Options */}
          <div className="space-y-3">
            <div className="flex items-center space-x-2">
              <Checkbox
                id="timestamp"
                checked={includeTimestamp}
                onCheckedChange={(checked) => setIncludeTimestamp(checked === true)}
              />
              <Label htmlFor="timestamp" className="text-sm cursor-pointer">
                Include timestamp in filename
              </Label>
            </div>
            <div className="flex items-center space-x-2">
              <Checkbox
                id="metadata"
                checked={includeMetadata}
                onCheckedChange={(checked) => setIncludeMetadata(checked === true)}
              />
              <Label htmlFor="metadata" className="text-sm cursor-pointer">
                Include metadata (domain, date, record count)
              </Label>
            </div>
          </div>

          {/* File Size Estimate */}
          <div className="rounded-lg bg-muted/50 p-3 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Estimated size:</span>
              <span className="font-medium">
                {format === 'pdf' ? `${Math.round(data.length * 0.5)}KB` :
                 format === 'csv' ? `${Math.round(data.length * 0.3)}KB` :
                 `${Math.round(data.length * 0.8)}KB`}
              </span>
            </div>
            <div className="flex justify-between mt-1">
              <span className="text-muted-foreground">Records:</span>
              <span className="font-medium">{data.length}</span>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleExport} disabled={isExporting || !filename.trim()}>
            {isExporting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Exporting...
              </>
            ) : (
              <>
                <Download className="mr-2 h-4 w-4" />
                Export
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
