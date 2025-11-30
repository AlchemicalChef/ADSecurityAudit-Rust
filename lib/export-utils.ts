import jsPDF from 'jspdf'
import autoTable from 'jspdf-autotable'
import Papa from 'papaparse'

export type ExportFormat = 'pdf' | 'csv' | 'json'

export interface ExportOptions {
  format: ExportFormat
  filename: string
  title?: string
  includeTimestamp?: boolean
  includeMetadata?: boolean
}

export interface ExportMetadata {
  generatedAt: string
  generatedBy: string
  domain: string
  recordCount: number
}

export interface ExportColumn {
  header: string
  accessor: string | ((item: any) => string)
  width?: number  // For PDF column width
}

// PDF Implementation
export function exportToPDF<T>(
  data: T[],
  columns: ExportColumn[],
  title: string,
  metadata?: ExportMetadata
): Blob {
  const doc = new jsPDF({
    orientation: 'landscape',
    unit: 'mm',
    format: 'a4'
  })

  // Add header with logo/title
  doc.setFontSize(18)
  doc.text(title, 14, 20)

  // Add metadata section
  if (metadata) {
    doc.setFontSize(10)
    const formattedDate = new Date(metadata.generatedAt).toLocaleString()
    doc.text(`Generated: ${formattedDate}`, 14, 28)
    doc.text(`Domain: ${metadata.domain}`, 14, 33)
    doc.text(`Records: ${metadata.recordCount}`, 14, 38)
  }

  // Prepare table data
  const headers = columns.map(col => col.header)
  const body = data.map(item =>
    columns.map(col => {
      if (typeof col.accessor === 'function') {
        return col.accessor(item)
      }
      return String(item[col.accessor as keyof T] ?? '')
    })
  )

  // Add table
  autoTable(doc, {
    head: [headers],
    body: body,
    startY: metadata ? 45 : 30,
    theme: 'grid',
    styles: { fontSize: 8 },
    headStyles: { fillColor: [41, 128, 185] },
    alternateRowStyles: { fillColor: [242, 242, 242] },
    margin: { top: 10 }
  })

  // Add page numbers
  const pageCount = (doc as any).internal.getNumberOfPages()
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i)
    doc.setFontSize(8)
    doc.text(
      `Page ${i} of ${pageCount}`,
      doc.internal.pageSize.width / 2,
      doc.internal.pageSize.height - 10,
      { align: 'center' }
    )
  }

  return doc.output('blob')
}

// CSV Implementation
export function exportToCSV<T>(
  data: T[],
  columns: ExportColumn[]
): string {
  const headers = columns.map(col => col.header)
  const rows = data.map(item =>
    columns.map(col => {
      if (typeof col.accessor === 'function') {
        return col.accessor(item)
      }
      const value = item[col.accessor as keyof T]
      return value != null ? String(value) : ''
    })
  )

  return Papa.unparse({
    fields: headers,
    data: rows
  })
}

// JSON Implementation
export function exportToJSON<T>(
  data: T[],
  metadata?: ExportMetadata
): string {
  const exportData = {
    metadata: metadata || {
      generatedAt: new Date().toISOString(),
      recordCount: data.length
    },
    data: data
  }

  return JSON.stringify(exportData, null, 2)
}

// Helper to trigger download
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export function downloadText(text: string, filename: string, mimeType: string): void {
  const blob = new Blob([text], { type: mimeType })
  downloadBlob(blob, filename)
}

// Main export function
export async function exportData<T>(
  data: T[],
  columns: ExportColumn[],
  options: ExportOptions,
  metadata?: ExportMetadata
): Promise<void> {
  const { format, filename, title, includeTimestamp } = options

  const finalFilename = includeTimestamp
    ? `${filename}_${new Date().toISOString().split('T')[0]}.${format}`
    : `${filename}.${format}`

  switch (format) {
    case 'pdf': {
      const blob = exportToPDF(data, columns, title || filename, metadata)
      downloadBlob(blob, finalFilename)
      break
    }
    case 'csv': {
      const csv = exportToCSV(data, columns)
      downloadText(csv, finalFilename, 'text/csv')
      break
    }
    case 'json': {
      const json = exportToJSON(data, metadata)
      downloadText(json, finalFilename, 'application/json')
      break
    }
  }
}
