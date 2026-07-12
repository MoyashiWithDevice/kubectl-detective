package export

import (
	"io"
	"strings"
	"text/template"
)

var htmlTmpl = template.Must(template.New("html").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>kubectl-detective Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; margin: 2rem; background: #fafafa; color: #333; }
  h1 { font-size: 1.4rem; border-bottom: 2px solid #333; padding-bottom: 0.3rem; }
  h2 { font-size: 1.1rem; margin-top: 1.5rem; }
  .meta { color: #666; margin-bottom: 1.5rem; font-size: 0.9rem; }
  table { border-collapse: collapse; width: 100%; max-width: 720px; }
  th, td { text-align: left; padding: 0.4rem 0.8rem; border-bottom: 1px solid #ddd; }
  th { background: #eee; font-weight: 600; }
  tr:hover { background: #f5f5f5; }
  pre, .mermaid { background: #fff; padding: 1rem; border: 1px solid #ddd; border-radius: 4px; max-width: 720px; overflow-x: auto; white-space: pre; font-size: 0.85rem; }
</style>
</head>
<body>
<h1>kubectl-detective Service Map</h1>
<div class="meta">
  Generated: {{.Timestamp}}<br>
  Duration: {{.Duration}}<br>
  Total flows: {{.FlowCount}}
</div>

<h2>ASCII</h2>
<pre>{{.ASCII}}</pre>

<h2>Mermaid</h2>
<div class="mermaid">{{.Mermaid}}</div>

<h2>Edge List</h2>
<table>
<thead><tr><th>Source</th><th>Destination</th><th>Connections</th></tr></thead>
<tbody>
{{range .EdgeRows}}<tr><td>{{.Source}}</td><td>{{.Destination}}</td><td>{{.Count}}</td></tr>
{{end}}</tbody>
</table>
</body>
</html>
`))

type htmlData struct {
	Timestamp string
	Duration  string
	FlowCount int
	ASCII     string
	Mermaid   string
	EdgeRows  []edgeRow
}

type edgeRow struct {
	Source      string
	Destination string
	Count       int
}

func WriteHTML(w io.Writer, r *Report) error {
	edges := r.Graph.Edges()

	rows := make([]edgeRow, len(edges))
	for i, e := range edges {
		rows[i] = edgeRow{Source: e.Source, Destination: e.Destination, Count: e.Count}
	}

	data := htmlData{
		Timestamp: r.Timestamp.Format("2006-01-02 15:04:05"),
		Duration:  r.Duration.String(),
		FlowCount: r.FlowCount(),
		ASCII:     r.Graph.ASCII(),
		Mermaid:   r.Graph.Mermaid(),
		EdgeRows:  rows,
	}

	return htmlTmpl.Execute(w, data)
}

func FormatHTML(r *Report) string {
	var b strings.Builder
	_ = WriteHTML(&b, r)
	return b.String()
}
