extends Node
class_name SubGraph

signal select_node

var id: String = ""
var root: Object = null
var nodes: Dictionary = {}
var edges: Array = []

var node_group: Spatial = null
var line_group: Spatial = null


func add_node_layout():
	var center = Spatial.new()
	center.name = "Center"
	add_child(center)

	var graph = Spatial.new()
	graph.name = "Graph"
	center.add_child(graph)

	line_group = Spatial.new()
	line_group.name = "LineGroup"
	line_group.translation.z = -5
	graph.add_child(line_group)

	node_group = Spatial.new()
	node_group.name = "NodeGroup"
	graph.add_child(node_group)
