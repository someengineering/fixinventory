extends Node
class_name CloudGraph

signal order_done

var graph_data := {
	"nodes" : {},
	"edges" : {}
	}

const ATTRACTION_CONSTANT := 0.3*0.05
const REPULSION_CONSTANT := 400.0
const MAX_DISTANCE := 1000.0
const GRAPH_MOVE_SPEED := 1.2

const DEFAULT_DAMPING := 0.7
const DEFAULT_SPRING_LENGTH := 200/3
const DEFAULT_MAX_ITERATIONS := 200


var cloud_node_icon = preload("res://ui/elements/Element_CloudNode.tscn")
var root_node : Object = null

onready var node_group = $Center/Graph/NodeGroup
onready var line_group = $Center/Graph/LineGroup


func _ready():
	_e.connect("hovering_node", self, "hovering_node")
	_e.connect("show_connected_nodes", self, "show_connected_nodes")


func create_graph(raw_data : Dictionary):
	for data in raw_data.values():
		if data != null and data.has("id"):
			graph_data.nodes[data.id] = create_new_node(data)
			if root_node == null:
				root_node = graph_data.nodes[data.id].icon
		elif graph_data.nodes.has(data.from) and graph_data.nodes.has(data.to):
			# For SFDP creation
			graph_data.nodes[data.from].to.append( graph_data.nodes[data.to].icon )
			graph_data.nodes[data.to].from.append( graph_data.nodes[data.from].icon )
			# For connection lines
			graph_data.edges[str(data.from + data.to)] = add_connection(data)


func create_new_node(_data:Dictionary) -> CloudNode:
	var new_cloud_node = CloudNode.new()
	new_cloud_node.id = _data.id
	new_cloud_node.reported = _data.reported
	new_cloud_node.kind = _data.reported.kind
	
	new_cloud_node.icon = cloud_node_icon.instance()
	new_cloud_node.icon.cloud_node = new_cloud_node
	new_cloud_node.icon.position = Vector2(1920,1080*1.8)*0.5
	node_group.add_child(new_cloud_node.icon)
	
	return new_cloud_node


func add_connection(_data:Dictionary) -> CloudConnection:
	var new_connection = CloudConnection.new()
	new_connection.from = graph_data.nodes[_data.from]
	new_connection.to = graph_data.nodes[_data.to]
	
	var new_connection_line = Line2D.new()
	new_connection_line.width = 2
	new_connection_line.default_color = new_connection.color
	new_connection.line = new_connection_line
	line_group.add_child(new_connection_line)
	
	return new_connection


func show_connected_nodes(node_id):
	var nodes_to_activate = [node_id]
	for connection in graph_data.edges.values():
		if connection.from.id == node_id and !nodes_to_activate.has(connection.to.id):
			nodes_to_activate.append(connection.to.id)
		elif connection.to.id == node_id and !nodes_to_activate.has(connection.from.id):
			nodes_to_activate.append(connection.from.id)
	_e.emit_signal("hide_nodes")
	for n in nodes_to_activate:
		_e.emit_signal("show_node", n)


func graph_calc_layout():
	center_diagram()
	arrange(DEFAULT_DAMPING, DEFAULT_SPRING_LENGTH, DEFAULT_MAX_ITERATIONS, true)


func graph_rand_layout():
	for node in graph_data.nodes.values():
		if node.icon.random_pos == Vector2.ZERO:
			node.icon.random_pos = get_random_pos()
		node.icon.position = node.icon.random_pos
	root_node.position = Vector2.ZERO
	root_node.random_pos = Vector2.ZERO
	center_diagram()
	update_connection_lines()


func update_connection_lines() -> void:
	for connection in graph_data.edges.values():
		connection.line.global_position = connection.from.icon.global_position
		connection.line.points = PoolVector2Array( [Vector2.ZERO, connection.to.icon.global_position - connection.line.global_position ] )


func layout_graph(graph_node_positions := {}) -> void:
	if graph_node_positions.empty() or graph_node_positions.size() != graph_data.nodes.size():
		for node in graph_data.nodes.values():
			node.icon.position = get_random_pos()
			node.icon.random_pos = node.icon.position
	else:
		for node in graph_data.nodes.values():
			node.icon.position = str2var(graph_node_positions[node.id])
			node.icon.graph_pos = node.icon.position
	update_connection_lines()
	center_diagram()


func get_random_pos() -> Vector2:
	return Vector2(randf()*2000 + 100, 0).rotated(randf()*TAU)


func hovering_node(node_id, power) -> void:
	for connection in graph_data.edges.values():
		if connection.to.id == node_id or connection.from.id == node_id:
			var line_color = Color(5,3,1,1) if connection.to.id == node_id else Color(3,4,5,1)
			connection.line.self_modulate = lerp(Color.white, line_color*1.5, power)


func calc_repulsion_force_pos(node_a_pos, node_b_pos):
	var proximity : float = max( node_a_pos.distance_to(node_b_pos), 1 )
	var force = -REPULSION_CONSTANT/proximity
	var dir = node_a_pos.direction_to(node_b_pos)
	return dir*force


func calc_attraction_force_pos(node_a_pos, node_b_pos, spring_length):
	var proximity : float = max( node_a_pos.distance_to(node_b_pos), 1 )
	var force = ATTRACTION_CONSTANT * max(proximity - spring_length, 0)
	var dir = node_a_pos.direction_to(node_b_pos)
	return dir*force

# Arrange the graph using SFDP
# returning the nodes positions
func arrange(damping, spring_length, max_iterations, deterministic := false):
	if !deterministic:
		randomize()
	
	var stop_count = 0
	var iterations = 0
	
	var nodes_keys : Array = Array( graph_data.nodes.keys() )
	
	while true:
		var total_displacement := 0.0
		
		for i in graph_data.nodes.size():
			var node = graph_data.nodes[ nodes_keys[i] ]
			var current_node_position = node.icon.position
			var net_force = Vector2.ZERO
			
			
			for other_node in graph_data.nodes.values():
				if node != other_node:
					var other_node_pos = other_node.icon.position
					if current_node_position.distance_to(other_node_pos) > MAX_DISTANCE:
						continue
					net_force += calc_repulsion_force_pos( current_node_position, other_node_pos )
			
			for child_node in node.to:
				net_force += calc_attraction_force_pos( current_node_position, child_node.position, spring_length )

			for parent in node.from:
				net_force += calc_attraction_force_pos( current_node_position, parent.position, spring_length)
			
			node.velocity = (node.velocity + net_force) * damping * GRAPH_MOVE_SPEED
			node.next_pos = (current_node_position + node.velocity)
			total_displacement += node.velocity.length()
		
		for i in graph_data.nodes.size():
			var node = graph_data.nodes[ nodes_keys[i] ]
			graph_data.nodes[ nodes_keys[i] ].icon.position = node.next_pos

		iterations += 1
		if total_displacement < 10:
			stop_count += 1
		if stop_count > 15:
			break
		if iterations > max_iterations:
			break
		
		center_diagram()
		update_connection_lines()
		yield(get_tree(), "idle_frame")
	
	var saved_node_positions := {}
	for node in graph_data.nodes.values():
		saved_node_positions[node.id] = var2str(node.icon.position)
		node.icon.graph_pos = node.icon.position
	
	emit_signal("order_done", saved_node_positions)


func center_diagram():
	$Center/Graph.position = -root_node.position# + Vector2(1920, 1080)/2


func get_cloudgraph_from_selection(node_id) -> Dictionary:
	var new_cloudgraph = {
		"nodes" : {},
		"edges" : {}
		}
	
	var connection_keys = _g.main_graph.graph_data.edges.keys()
	for connection_key in connection_keys:
		var connection = _g.main_graph.graph_data.edges[ connection_key ]
		if [connection.from.id, connection.to.id].has(node_id) and !new_cloudgraph.edges.has(connection_key):
			new_cloudgraph.edges[connection_key] = connection
	
	var nodes = _g.main_graph.graph_data.nodes
	for connection in new_cloudgraph.edges.values():
		var connection_id_from = connection.from.id
		var connection_id_to = connection.to.id
		if nodes.has(connection_id_from) and !new_cloudgraph.nodes.has(connection_id_from):
			new_cloudgraph.nodes[connection_id_from] = nodes[connection_id_from].duplicate()
		elif nodes.has(connection_id_to) and !new_cloudgraph.nodes.has(connection_id_to):
			new_cloudgraph.nodes[connection_id_to] = nodes[connection_id_to].duplicate()

	return new_cloudgraph


func get_blastradius_from_selection(node_id):
	var new_cloudgraph = {
		"nodes" : {},
		"edges" : {}
		}
	new_cloudgraph.nodes[node_id] = _g.main_graph.graph_data.nodes[node_id]
	var iterations := 0
	var all_children_resolved := false
	var next_layer : Dictionary = new_cloudgraph.duplicate()
	var last_layer := { "nodes" : {},"edges" : {} }
	while !all_children_resolved:
		all_children_resolved = true
		last_layer = { "nodes" : {},"edges" : {} }
		
		for node in new_cloudgraph.nodes.values():
			var connection_keys = _g.main_graph.graph_data.edges.keys()
			for connection_key in connection_keys:
				var connection = _g.main_graph.graph_data.edges[ connection_key ]
				
				if connection.from.id == node.id and !next_layer.edges.has(connection_key):
					next_layer = get_children_from_selection(node.id, next_layer)
					
					all_children_resolved = false
		new_cloudgraph = merge_cloudgraphs(new_cloudgraph, next_layer)
		iterations += 1
	return new_cloudgraph


func merge_cloudgraphs(original:Dictionary, update:Dictionary) -> Dictionary:
	for node in update.nodes.keys():
		original.nodes[node] = update.nodes[node]
	
	for edge in update.edges.keys():
		original.edges[edge] = update.edges[edge]
	
	return original


func get_children_from_selection(node_id, new_cloudgraph) -> Dictionary:
	var connection_keys = _g.main_graph.graph_data.edges.keys()
	for connection_key in connection_keys:
		var connection = _g.main_graph.graph_data.edges[ connection_key ]
		if connection.from.id == node_id:
			new_cloudgraph.edges[connection_key] = connection
	
	var nodes = _g.main_graph.graph_data.nodes
	for connection in new_cloudgraph.edges.values():
		var connection_id = connection.to.id
		if nodes.has(connection_id):
			new_cloudgraph.nodes[connection_id] = nodes[connection_id]
	
	return new_cloudgraph
