extends Polygon2D

var node_name = "none"
var node_kind = "none"
var connections := []

func add_child_node(node):
	if !connections.has(node):
		connections.append(node)
