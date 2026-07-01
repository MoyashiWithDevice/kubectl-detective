package graph

type Edge struct {
	Source      string
	Destination string
	Count       int
}

type Graph struct {
	edges map[string]map[string]*Edge
}

func New() *Graph {
	return &Graph{edges: make(map[string]map[string]*Edge)}
}

func (g *Graph) AddEdge(src, dst string) {
	if g.edges[src] == nil {
		g.edges[src] = make(map[string]*Edge)
	}
	if e, ok := g.edges[src][dst]; ok {
		e.Count++
	} else {
		g.edges[src][dst] = &Edge{
			Source:      src,
			Destination: dst,
			Count:       1,
		}
	}
}

func (g *Graph) Edges() []*Edge {
	var result []*Edge
	for _, dstMap := range g.edges {
		for _, e := range dstMap {
			result = append(result, e)
		}
	}
	return result
}
