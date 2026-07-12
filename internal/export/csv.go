package export

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

func WriteCSV(w io.Writer, r *Report) error {
	bw := csv.NewWriter(w)

	if err := bw.Write([]string{"source", "destination", "connections"}); err != nil {
		return err
	}

	for _, e := range r.Graph.Edges() {
		if err := bw.Write([]string{
			e.Source,
			e.Destination,
			fmt.Sprintf("%d", e.Count),
		}); err != nil {
			return err
		}
	}

	bw.Flush()
	return bw.Error()
}

func FormatCSV(r *Report) string {
	var b strings.Builder
	_ = WriteCSV(&b, r)
	return b.String()
}
