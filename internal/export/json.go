package export

import (
	"encoding/json"
	"io"
	"strings"
	"time"
)

type jsonEdge struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Count       int    `json:"connections"`
}

type jsonReport struct {
	Timestamp string     `json:"timestamp"`
	Duration  string     `json:"duration"`
	FlowCount int        `json:"flow_count"`
	Edges     []jsonEdge `json:"edges"`
}

func WriteJSON(w io.Writer, r *Report) error {
	edges := r.Graph.Edges()
	jEdges := make([]jsonEdge, len(edges))
	for i, e := range edges {
		jEdges[i] = jsonEdge{
			Source:      e.Source,
			Destination: e.Destination,
			Count:       e.Count,
		}
	}

	jr := jsonReport{
		Timestamp: r.Timestamp.Format(time.RFC3339),
		Duration:  r.Duration.String(),
		FlowCount: r.FlowCount(),
		Edges:     jEdges,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jr)
}

func FormatJSON(r *Report) string {
	var b strings.Builder
	_ = WriteJSON(&b, r)
	return b.String()
}
