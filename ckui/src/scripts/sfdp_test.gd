extends Node2D

var cloud_node_icon = preload("res://ui/elements/Element_CloudNode.tscn")

const ATTRACTION_CONSTANT := 0.3*0.05
const REPULSION_CONSTANT := 400.0
const MAX_DISTANCE := 1000.0

const DEFAULT_DAMPING := 0.7
const DEFAULT_SPRING_LENGTH := 200/3
const DEFAULT_MAX_ITERATIONS := 300

var nodes := {}

onready var node_group = $Center/Graph/NodeGroup
onready var line_group = $Center/Graph/LineGroup

func _ready():
	read_data()
	nodes = _g.nodes.duplicate()
	center_diagram()
	yield(get_tree().create_timer(10), "timeout")
	arrange(DEFAULT_DAMPING, DEFAULT_SPRING_LENGTH, DEFAULT_MAX_ITERATIONS, true);


func read_data():
	var file = File.new()
	file.open("res://data/graph_dump.json", file.READ)
	var new_data := {}
	var index = 0
	while not file.eof_reached():
		var line = file.get_line()
		if line == "":
			index += 1
			continue
		new_data[index] = parse_json(line)
		index += 1
	file.close()
	
	for data in new_data.values():
		if data != null and data.has("id"):
			_g.nodes[data.id] = create_new_node(data)
		elif _g.nodes.has(data.from) and _g.nodes.has(data.to):
			#just for sfdp testing
			_g.nodes[data.from].to.append( _g.nodes[data.to].icon )
			_g.nodes[data.to].from.append( _g.nodes[data.from].icon )
			
			_g.connections[str(data.from + data.to)] = add_connection(data)
	
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
	new_connection_line.default_color = Color(0.7,0.9,1,0.2)
	new_connection.line = new_connection_line
	line_group.add_child(new_connection_line)
	
	return new_connection


func update_connection_lines() -> void:
	for connection in _g.connections.values():
		connection.line.global_position = connection.from.icon.global_position
		connection.line.points = PoolVector2Array( [Vector2.ZERO, connection.to.icon.global_position - connection.line.global_position ] )


func layout_graph() -> void:
	for node in _g.nodes.values():
		node.icon.position = Vector2(rand_range(-1000, 1000), rand_range(-1000, 1000)) + Vector2(-2880, -1630)


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
	
	var nodes_keys : Array = Array( nodes.keys() )
	
	while true:
		var total_displacement := 0.0
		
		for i in nodes.size():
			var node = nodes[ nodes_keys[i] ]
			var current_node_position = node.icon.position
			var net_force = Vector2.ZERO
			
			if i == 2:
				$Camera2D.global_position = node.icon.global_position
				$Camera2D.zoom *= 1.01
			
			
			for other_node in nodes.values():
				if node != other_node:
					var other_node_pos = other_node.icon.position
					if current_node_position.distance_to(other_node_pos) > MAX_DISTANCE:
						continue
					net_force += calc_repulsion_force_pos( current_node_position, other_node_pos )
			
			for child_node in node.to:
				net_force += calc_attraction_force_pos( current_node_position, child_node.position, spring_length )

			for parent in node.from:
				net_force += calc_attraction_force_pos( current_node_position, parent.position, spring_length)
			
			node.velocity = (node.velocity + net_force) * damping
			node.next_pos = (current_node_position + node.velocity)
			total_displacement += node.velocity.length()
		
		for i in nodes.size():
			var node = nodes[ nodes_keys[i] ]
			nodes[ nodes_keys[i] ].icon.position = node.next_pos

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
	for node in nodes.values():
		saved_node_positions[node.id] = var2str(node.icon.position)
	
	Utils.save_json(_g.GRAPH_NODE_JSON_PATH, saved_node_positions)
	

func center_diagram():
	$Center/Graph.position = -nodes[ Array(nodes.keys())[0] ].icon.position# + Vector2(1920, 1080)/2
