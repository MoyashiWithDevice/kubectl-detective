package graph

import (
	"fmt"
	"sort"
	"strings"
)

func (g *Graph) Mermaid() string {
	edges := g.Edges()
	if len(edges) == 0 {
		return "graph LR\n    (no edges)"
	}

	nodes := make(map[string]bool)
	for _, e := range edges {
		nodes[e.Source] = true
		nodes[e.Destination] = true
	}

	var sortedNodes []string
	for n := range nodes {
		sortedNodes = append(sortedNodes, n)
	}
	sort.Strings(sortedNodes)

	var b strings.Builder
	b.WriteString("graph LR\n")

	for _, n := range sortedNodes {
		id := sanitizeNodeID(n)
		if id != n {
			fmt.Fprintf(&b, "    %s[%s]\n", id, n)
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Source != edges[j].Source {
			return edges[i].Source < edges[j].Source
		}
		return edges[i].Destination < edges[j].Destination
	})

	for _, e := range edges {
		srcID := sanitizeNodeID(e.Source)
		dstID := sanitizeNodeID(e.Destination)
		label := ""
		if e.Count > 1 {
			label = fmt.Sprintf(" |%d flows|", e.Count)
		}
		fmt.Fprintf(&b, "    %s -->%s %s\n", srcID, label, dstID)
	}

	return b.String()
}

func sanitizeNodeID(name string) string {
	var result strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			result.WriteRune(r)
		} else {
			result.WriteRune('_')
		}
	}
	id := result.String()
	if id == "" {
		id = "node"
	}
	if id[0] >= '0' && id[0] <= '9' {
		id = "n" + id
	}
	return id
}
