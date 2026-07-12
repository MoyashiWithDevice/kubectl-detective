package graph

import (
	"fmt"
	"sort"
	"strings"
)

func (g *Graph) ASCII() string {
	edges := g.Edges()
	if len(edges) == 0 {
		return "(no edges)"
	}

	type outEdge struct {
		dst   string
		count int
	}

	srcEdges := make(map[string][]outEdge)
	allNodes := make(map[string]bool)
	for _, e := range edges {
		srcEdges[e.Source] = append(srcEdges[e.Source], outEdge{e.Destination, e.Count})
		allNodes[e.Source] = true
		allNodes[e.Destination] = true
	}

	var srcs []string
	for s := range srcEdges {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)

	for _, s := range srcs {
		sort.Slice(srcEdges[s], func(i, j int) bool {
			return srcEdges[s][i].dst < srcEdges[s][j].dst
		})
	}

	var b strings.Builder

	for i, src := range srcs {
		if i > 0 {
			b.WriteString("\n")
		}
		outs := srcEdges[src]
		if len(outs) == 1 {
			o := outs[0]
			fmt.Fprintf(&b, "%s ──→ %s", src, o.dst)
			if o.count > 1 {
				fmt.Fprintf(&b, "  (%d connections)", o.count)
			}
			b.WriteString("\n")
			continue
		}
		b.WriteString(src + "\n")
		for j, o := range outs {
			prefix := "  ├─→ "
			if j == len(outs)-1 {
				prefix = "  └─→ "
			}
			fmt.Fprintf(&b, "%s%s", prefix, o.dst)
			if o.count > 1 {
				fmt.Fprintf(&b, "  (%d connections)", o.count)
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

func (g *Graph) String() string {
	return g.ASCII()
}
