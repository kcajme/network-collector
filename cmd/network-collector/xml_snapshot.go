package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

type snapshotNode struct {
	Name     string         `json:"name"`
	Text     string         `json:"text,omitempty"`
	Children []snapshotNode `json:"children,omitempty"`
}

// XML snapshots ignore namespace prefix spelling, insignificant whitespace and
// sibling order. Namespace URIs and element/value associations remain intact.
// Attributes are excluded; this parser is for filtered operational element data.
func parseXMLSnapshot(output, root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("xml_snapshot requires a root in {namespace}local-name form")
	}
	if len(output) > 8*1024*1024 {
		return "", fmt.Errorf("XML snapshot exceeds 8 MiB")
	}
	decoder := xml.NewDecoder(strings.NewReader(output))
	stack := []snapshotNode{}
	nodes, roots := 0, 0
	documents := 0
	var result string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		switch v := token.(type) {
		case xml.Directive:
			return "", fmt.Errorf("XML directives are not accepted in snapshots")
		case xml.StartElement:
			if len(stack) == 0 {
				documents++
			}
			nodes++
			if nodes > 100000 || len(stack) >= 128 {
				return "", fmt.Errorf("XML snapshot complexity limit exceeded")
			}
			stack = append(stack, snapshotNode{Name: "{" + v.Name.Space + "}" + v.Name.Local})
		case xml.CharData:
			if len(stack) == 0 && strings.TrimSpace(string(v)) != "" {
				return "", fmt.Errorf("text outside XML document")
			}
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(v)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return "", fmt.Errorf("unbalanced XML snapshot")
			}
			node := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			node.Text = strings.TrimSpace(node.Text)
			sort.Slice(node.Children, func(i, j int) bool {
				a, _ := json.Marshal(node.Children[i])
				b, _ := json.Marshal(node.Children[j])
				return string(a) < string(b)
			})
			data, _ := json.Marshal(node)
			if node.Name == root {
				roots++
				result = string(data)
			}
			if len(stack) > 0 {
				stack[len(stack)-1].Children = append(stack[len(stack)-1].Children, node)
			}
		}
	}
	if documents != 1 || len(stack) != 0 || roots != 1 {
		return "", fmt.Errorf("expected exactly one XML snapshot root %q, got %d", root, roots)
	}
	// Keep the canonical representation as a JSON value usable by @this checks.
	return result, nil
}
