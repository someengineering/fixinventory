extends Control

var node_distance := {}

onready var graph_view = $GraphView

func _ready():
	_e.connect("show_blastradius", self, "show_blastradius")
	_e.disconnect("hovering_node", graph_view, "hovering_node")
	_e.disconnect("show_connected_nodes", graph_view, "show_connected_nodes")


func show_blastradius(node_id):
	var blastradius = get_blastradius_from_selection(node_id)
	graph_view.create_graph_direct(blastradius)
	graph_view.graph_rand_layout()
	graph_view.graph_calc_layout()
	graph_view.update_connection_lines()
	for node in graph_view.graph_data.nodes.values():
		node.icon.show_detail(node.id)


func get_blastradius_from_selection(node_id):
	node_distance.clear()
	var new_cloudgraph = {
		"nodes" : {},
		"edges" : {}
		}
	new_cloudgraph.nodes[node_id] = _g.main_graph.graph_data.nodes[node_id]
	var iterations := 0
	var all_children_resolved := false
	var next_layer : Dictionary = new_cloudgraph.duplicate()
	var current_layer : Dictionary = {}
	current_layer["nodes"] = []
	
	while !all_children_resolved:
		all_children_resolved = true
		current_layer["nodes"].clear()
		current_layer["nodes"] = next_layer.nodes.duplicate()
		
		for node in next_layer.nodes.values():
			# set the node distance from center
			node_distance[node.id] = iterations
			var edge_keys = _g.main_graph.graph_data.edges.keys()
			for edge_key in edge_keys:
				var connection = _g.main_graph.graph_data.edges[ edge_key ]
				if connection.from.id == node.id and !next_layer.edges.has(edge_key):
					next_layer = get_children_from_selection(node.id, next_layer)
					all_children_resolved = false
		
		new_cloudgraph = merge_cloudgraphs(new_cloudgraph, next_layer, iterations)
		next_layer = clean_duplicate_nodes(next_layer, current_layer)
		iterations += 1

	return new_cloudgraph


func merge_cloudgraphs(original:Dictionary, update:Dictionary, iterations:int) -> Dictionary:
	for node in update.nodes.keys():
		if !original.nodes.has(node):
			original.nodes[node] = update.nodes[node]
			node_distance[node] = iterations
	
	for edge in update.edges.keys():
		if !original.edges.has(edge):
			original.edges[edge] = update.edges[edge]
	
	original["nodes"] = original["nodes"].duplicate()
	original["edges"] = original["edges"].duplicate()
	return original


func clean_duplicate_nodes(original:Dictionary, update:Dictionary) -> Dictionary:
	for node in update.nodes.keys():
		original.nodes.erase(node)
	
		var edge_keys = original.edges.keys()
		for edge_key in edge_keys:
			var edge = original.edges[edge_key]
			if edge.from.id == node:
				original.edges.erase(edge_key)
		
	return original


func get_children_from_selection(node_id, new_cloudgraph) -> Dictionary:
	var edge_keys = _g.main_graph.graph_data.edges.keys()
	for edge_key in edge_keys:
		var connection = _g.main_graph.graph_data.edges[ edge_key ]
		if connection.from.id == node_id:
			new_cloudgraph.edges[edge_key] = connection
	
	var nodes = _g.main_graph.graph_data.nodes
	for connection in new_cloudgraph.edges.values():
		var connection_id = connection.to.id
		if nodes.has(connection_id) and connection_id != node_id:
			new_cloudgraph.nodes[connection_id] = nodes[connection_id]
	
	return new_cloudgraph
