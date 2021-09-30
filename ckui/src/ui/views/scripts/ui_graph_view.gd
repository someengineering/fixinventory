extends Node2D

const GRAPH_DUMP_JSON_PATH = "res://data/graph_dump.json"
const GRAPH_NODE_JSON_PATH := "res://data/graph_node_positions.json"

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

export (NodePath) onready var graph_cam = get_node(graph_cam)
export (NodePath) onready var graph_bg = get_node(graph_bg)


func _ready():
	_g.connect("load_nodes", self, "read_data")
	_e.connect("hovering_node", self, "hovering_node")
	_e.connect("show_connected_nodes", self, "show_connected_nodes")
	_e.connect("graph_order", self, "graph_calc_layout")
	_e.connect("graph_randomize", self, "graph_rand_layout")


func _process(delta):
	if root_node == null:
		return
	
	# move the center of the background gradient in the direction of the root node
	var dist_to_root_node = min(root_node.global_position.distance_to(graph_cam.global_position), 2000)
	var dir_to_root_node = root_node.global_position.direction_to(graph_cam.global_position)
	var zoom_factor = range_lerp(graph_cam.zoom.x, 0.5, 4, 1, 0.1)
	graph_bg.material.set_shader_param("center", -dir_to_root_node * ease(range_lerp(dist_to_root_node, 0, 2000, 0, 1), 0.7) * zoom_factor)


func graph_calc_layout():
	center_diagram()
	arrange(DEFAULT_DAMPING, DEFAULT_SPRING_LENGTH, DEFAULT_MAX_ITERATIONS, true)


func graph_rand_layout():
	for node in _g.nodes.values():
		if node.icon.random_pos == Vector2.ZERO:
			node.icon.random_pos = get_random_pos()
		node.icon.position = node.icon.random_pos
	root_node.position = Vector2.ZERO
	root_node.random_pos = Vector2.ZERO
	center_diagram()
	update_connection_lines()


func read_data():
	var file = File.new()
	var new_data := {}
	
	if file.file_exists(GRAPH_DUMP_JSON_PATH) and !_g.use_example_data:
		file.open(GRAPH_DUMP_JSON_PATH, file.READ)
		
		var index = 0
		while not file.eof_reached():
			var line = file.get_line()
			if line == "":
				index += 1
				continue
			new_data[index] = parse_json(line)
			index += 1
	
		file.close()
	else:
		var example_data_file = load("res://scripts/tools/example_data.gd")
		var example_data = example_data_file.new()
		new_data = example_data.graph_data.duplicate()
	
	for data in new_data.values():
		if data != null and data.has("id"):
			_g.nodes[data.id] = create_new_node(data)
			if root_node == null:
				root_node = _g.nodes[data.id].icon
		elif _g.nodes.has(data.from) and _g.nodes.has(data.to):
			# For SFDP creation
			_g.nodes[data.from].to.append( _g.nodes[data.to].icon )
			_g.nodes[data.to].from.append( _g.nodes[data.from].icon )
			# For connection lines
			_g.connections[str(data.from + data.to)] = add_connection(data)
	
	_g.emit_signal("nodes_changed")
	layout_graph()
	update_connection_lines()


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
	new_connection.from = _g.nodes[_data.from]
	new_connection.to = _g.nodes[_data.to]
	
	var new_connection_line = Line2D.new()
	new_connection_line.width = 2
	new_connection_line.default_color = new_connection.color
	new_connection.line = new_connection_line
	line_group.add_child(new_connection_line)
	
	return new_connection


func show_connected_nodes(node_id):
	var nodes_to_activate = [node_id]
	for connection in _g.connections.values():
		if connection.from.id == node_id and !nodes_to_activate.has(connection.to.id):
			nodes_to_activate.append(connection.to.id)
		elif connection.to.id == node_id and !nodes_to_activate.has(connection.from.id):
			nodes_to_activate.append(connection.from.id)
	_e.emit_signal("hide_nodes")
	for n in nodes_to_activate:
		_e.emit_signal("show_node", n)


func update_connection_lines() -> void:
	for connection in _g.connections.values():
		connection.line.global_position = connection.from.icon.global_position
		connection.line.points = PoolVector2Array( [Vector2.ZERO, connection.to.icon.global_position - connection.line.global_position ] )


func layout_graph() -> void:
	var graph_node_positions = Utils.load_json(GRAPH_NODE_JSON_PATH)
	
	if graph_node_positions.empty() or graph_node_positions.size() != _g.nodes.size():
		for node in _g.nodes.values():
			node.icon.position = get_random_pos()
			node.icon.random_pos = node.icon.position
	else:
		for node in _g.nodes.values():
			node.icon.position = str2var(graph_node_positions[node.id])
			node.icon.graph_pos = node.icon.position


func get_random_pos() -> Vector2:
	return Vector2(rand_range(1000, 5760-1000), rand_range(550, 3240-550)) + Vector2(-2880, -1630)


func hovering_node(node_id, power) -> void:
	for connection in _g.connections.values():
		if connection.to.id == node_id or connection.from.id == node_id:
			var line_color = Color(5,3,1,1) if connection.to.id == node_id else Color(3,4,5,1)
			connection.line.self_modulate = lerp(Color.white, line_color*1.5, power)


func calc_repulsion_force_pos(node_a_pos, node_b_pos):
	var proximity : int = max( node_a_pos.distance_to(node_b_pos), 1 )
	var force = -REPULSION_CONSTANT/proximity
	var dir = node_a_pos.direction_to(node_b_pos)
	return dir*force


func calc_attraction_force_pos(node_a_pos, node_b_pos, spring_length):
	var proximity : int = max( node_a_pos.distance_to(node_b_pos), 1 )
	var force = ATTRACTION_CONSTANT * max(proximity - spring_length, 0)
	var dir = node_a_pos.direction_to(node_b_pos)
	return dir*force


func arrange(damping, spring_length, max_iterations, deterministic := false):
	if !deterministic:
		randomize()
	
	var stop_count = 0
	var iterations = 0
	
	var nodes_keys : Array = Array( _g.nodes.keys() )
	
	while true:
		var total_displacement := 0.0
		
		for i in _g.nodes.size():
			var node = _g.nodes[ nodes_keys[i] ]
			var current_node_position = node.icon.position
			var net_force = Vector2.ZERO
			
			
			for other_node in _g.nodes.values():
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
		
		for i in _g.nodes.size():
			var node = _g.nodes[ nodes_keys[i] ]
			_g.nodes[ nodes_keys[i] ].icon.position = node.next_pos

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
	
	var saved_node_positions : Dictionary
	for node in _g.nodes.values():
		saved_node_positions[node.id] = var2str(node.icon.position)
		node.icon.graph_pos = node.icon.position
	
	Utils.save_json(GRAPH_NODE_JSON_PATH, saved_node_positions)
	

func center_diagram():
	$Center/Graph.position = -root_node.position# + Vector2(1920, 1080)/2
