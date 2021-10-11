extends Node
class_name CloudGraph

signal hovering_node
signal show_node
signal hide_nodes
signal show_connected_nodes
signal order_done
signal graph_created

const ATTRACTION_CONSTANT := 0.3*0.05
const REPULSION_CONSTANT := 400.0
const MAX_DISTANCE := 1000.0
const GRAPH_MOVE_SPEED := 1.0
const MAX_DISPLACE := 100.0
const DEFAULT_DAMPING := 0.7
const DEFAULT_SPRING_LENGTH := 200/3
const DEFAULT_MAX_ITERATIONS := 200

var graph_data := {
	"nodes" : {},
	"edges" : {}
	}

var layout_data := {}

var cloud_node_scene = preload("res://ui/elements/Element_CloudNode.tscn")
var root_node : Object = null
var is_removed := false
var is_active := true
var update_visuals := true

var node_group : Node2D = null
var line_group : Node2D = null


func _ready():
	add_structure()
	connect("hovering_node", self, "hovering_node")
	connect("show_connected_nodes", self, "show_connected_nodes")


func add_structure():
	var center = Node2D.new()
	center.name = "Center"
	add_child(center)
	
	var graph = Node2D.new()
	graph.name = "Graph"
	center.add_child(graph)
	
	line_group = Node2D.new()
	line_group.name = "LineGroup"
	graph.add_child(line_group)
	
	node_group = Node2D.new()
	node_group.name = "NodeGroup"
	graph.add_child(node_group)


func add_node(_data:Dictionary) -> CloudNode:
	var new_cloud_node = CloudNode.new()
	new_cloud_node.id = _data.id
	new_cloud_node.reported = _data.reported
	new_cloud_node.kind = _data.reported.kind
	
	new_cloud_node.scene = cloud_node_scene.instance()
	new_cloud_node.scene.parent_graph = self
	new_cloud_node.scene.cloud_node = new_cloud_node
	node_group.add_child(new_cloud_node.scene)
	new_cloud_node.scene.position = get_random_pos()
	
	return new_cloud_node


func add_edge(_data:Dictionary) -> CloudEdge:
	var new_edge = CloudEdge.new()
	new_edge.from = graph_data.nodes[_data.from]
	new_edge.to = graph_data.nodes[_data.to]
	
	var new_edge_line = Line2D.new()
	new_edge_line.width = 2
	new_edge_line.default_color = new_edge.color
	new_edge.line = new_edge_line
	line_group.add_child(new_edge_line)
	
	return new_edge


func create_graph_raw(raw_data : Dictionary, total_nodes:int):
	_e.emit_signal("loading", 0, "Creating visual elements" )
	node_group.modulate.a = 0.05
	
	var index := 0
	var index_mod = max(raw_data.size() / 100, 1)
	var total_size : float = float( raw_data.size() )
	for data in raw_data.values():
		if index % index_mod == 0:
			_e.emit_signal("loading", float(index) / total_size, "Creating visual elements" )
			_g.msg( "Creating visual elements: {0}/{1}".format([index, total_nodes]) )
			yield(get_tree(), "idle_frame")
		index += 1
		if data == null:
			continue
		if "id" in data:
			graph_data.nodes[data.id] = add_node(data)
			create_new_layout_ref(data)
			if root_node == null:
				root_node = graph_data.nodes[data.id].scene
				
		else:
			# For SFDP creation
			layout_data[data.from].connections.append( layout_data[data.to] )
			layout_data[data.to].connections.append( layout_data[data.from] )
			
			# For connection lines
			graph_data.edges[index] = add_edge(data)
	
	node_group.modulate.a = 1
	emit_signal("graph_created")
	_g.msg( "Visual elements done ... rendering" )
	_e.emit_signal("loading", 1, "Creating visual elements" )
	_e.emit_signal("loading_done")


func create_new_layout_ref(data):
	var ref = NodeLayoutRef.new()
	ref.id = data.id
	layout_data[data.id] = ref


func create_graph_direct(_graph_data : Dictionary):
	var node_keys = _graph_data.nodes.keys()
	for node_key in node_keys:
		var node = _graph_data.nodes[node_key]
		node.scene = cloud_node_scene.instance()
		node.scene.cloud_node = node
		node.scene.position = Vector2(1920,1080*1.8)*0.5
		node.scene.parent_graph = self
		node_group.add_child(node.scene)
	
	var edge_keys = _graph_data.edges.keys()
	for edge_key in edge_keys:
		var edge = _graph_data.edges[edge_key]
		edge.from = _graph_data.nodes[edge.from.id]
		edge.to = _graph_data.nodes[edge.to.id]
		
		var new_edge_line = Line2D.new()
		new_edge_line.width = 2
		new_edge_line.default_color = edge.color
		edge.line = new_edge_line
		line_group.add_child(new_edge_line)
	
	if root_node == null:
		root_node = _graph_data.nodes[ node_keys[0] ].scene
	
	graph_data.nodes = _graph_data.nodes
	graph_data.edges = _graph_data.edges


func show_connected_nodes(node_id):
	if !is_active:
		return
	var nodes_to_activate = [node_id]
	for connection in graph_data.edges.values():
		if connection.from.id == node_id and !nodes_to_activate.has(connection.to.id):
			nodes_to_activate.append(connection.to.id)
		elif connection.to.id == node_id and !nodes_to_activate.has(connection.from.id):
			nodes_to_activate.append(connection.from.id)
	emit_signal("hide_nodes")
	for n in nodes_to_activate:
		emit_signal("show_node", n)


func graph_calc_layout():
	center_diagram()
	arrange(DEFAULT_DAMPING, DEFAULT_SPRING_LENGTH, DEFAULT_MAX_ITERATIONS, true)


func graph_rand_layout():
	for node in graph_data.nodes.values():
		if node.scene.random_pos == Vector2.ZERO:
			node.scene.random_pos = get_random_pos()
		node.scene.position = node.scene.random_pos
		layout_data[node.id].position = node.scene.position
	root_node.position = Vector2.ZERO
	root_node.random_pos = Vector2.ZERO
	center_diagram()
	update_connection_lines()


func update_connection_lines() -> void:
	for connection in graph_data.edges.values():
		connection.line.global_position = connection.from.scene.global_position
		connection.line.points = PoolVector2Array( [Vector2.ZERO, connection.to.scene.global_position - connection.line.global_position ] )


func layout_graph(graph_node_positions := {}) -> void:
	if graph_node_positions.empty() or graph_node_positions.size() != graph_data.nodes.size():
		for node in graph_data.nodes.values():
			node.scene.position = get_random_pos()
			node.scene.random_pos = node.scene.position
			layout_data[node.id].position = node.scene.position
	else:
		for node in graph_data.nodes.values():
			node.scene.position = str2var(graph_node_positions[node.id])
			node.scene.graph_pos = node.scene.position
			layout_data[node.id].position = node.scene.position
	
	update_connection_lines()
	center_diagram()


func layout_to_real_pos():
	for node in graph_data.nodes.values():
		node.scene.position = layout_data[node.id].position 


func real_to_layout_pos():
	for node in graph_data.nodes.values():
		layout_data[node.id].position = node.scene.position


func get_random_pos() -> Vector2:
	return Vector2(randf()*2000 + 100, 0).rotated(randf()*TAU)


func hovering_node(node_id, power) -> void:
	if !is_active:
		return
	for connection in graph_data.edges.values():
		if connection.to.id == node_id or connection.from.id == node_id and !is_removed:
			var line_color = Color(5,3,1,1) if connection.to.id == node_id else Color(3,4,5,1)
			if is_instance_valid(connection.line):
				connection.line.self_modulate = lerp(Color.white, line_color*1.5, power)


func show_all() -> void:
	emit_signal("hide_nodes")
	for connection in graph_data.edges.values():
		var line_color = Color(1,0.2,0.2,0.5)
		#connection.line.self_modulate = line_color
		connection.line.default_color = line_color
	for node in graph_data.nodes.values():
		node.scene.labels_unisize(0.25)


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
	var benchmark_start = OS.get_ticks_usec()
	if !deterministic:
		randomize()
	
	var stop_count = 0
	var iterations = 0
	
	var nodes_keys : Array = layout_data.keys()
	while true:
		var total_displacement := 0.0
		
		for key in nodes_keys:
			var node = layout_data[ key ]
			var current_node_position = node.position
			var net_force = Vector2.ZERO
			
			for other_node in layout_data.values():
				if node != other_node:
					var other_node_pos = other_node.position
					if other_node in node.connections:
						net_force += calc_attraction_force_pos( current_node_position, other_node_pos, spring_length )
					elif current_node_position.distance_to(other_node_pos) < MAX_DISTANCE:
						net_force += calc_repulsion_force_pos( current_node_position, other_node_pos )
					else:
						continue
			
			node.velocity = ((node.velocity + net_force) * damping * GRAPH_MOVE_SPEED).clamped(500.0)
			node.position += node.velocity
			total_displacement += node.velocity.length()
		
		prints("Calculated iterations: {0} | Total time passed: {1}".format([iterations, (OS.get_ticks_usec() - benchmark_start)/1000000.0 ]))
		
		iterations += 1
		if total_displacement < 10:
			stop_count += 1
		if stop_count > 15:
			break
		if iterations > max_iterations:
			break
		
		if update_visuals:
			center_diagram()
			layout_to_real_pos()
			update_connection_lines()
		yield(get_tree(), "idle_frame")
		
	
	if !update_visuals:
		center_diagram()
		layout_to_real_pos()
		update_connection_lines()
	
	var saved_node_positions := {}
	for node in graph_data.nodes.values():
		saved_node_positions[node.id] = var2str(node.scene.position)
		node.scene.graph_pos = node.scene.position
	
	var benchmark_end = OS.get_ticks_usec()
	var benchmark_time = (benchmark_end - benchmark_start)/1000000.0
	prints("Time to calculate {0} iterations: {1}".format([iterations, benchmark_time]))
	
	emit_signal("order_done", saved_node_positions)


func center_diagram():
	$Center/Graph.position = -root_node.position# + Vector2(1920, 1080)/2


func remove_graph():
	is_removed = true
	disconnect("hovering_node", self, "hovering_node")
	disconnect("show_connected_nodes", self, "show_connected_nodes")
	queue_free()
