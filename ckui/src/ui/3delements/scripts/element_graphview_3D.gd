extends Spatial
class_name CloudGraph3D

signal hovering_node
signal show_node
signal hide_nodes
signal show_connected_nodes
signal order_done
signal graph_created

const ATTRACTION_CONSTANT := 0.01
const REPULSION_CONSTANT := 100.0
const MAX_DISTANCE := 800.0
const GRAPH_MOVE_SPEED := 1.0
const MAX_DISPLACE := 50000.0
const DEFAULT_DAMPING := 0.95
const DEFAULT_SPRING_LENGTH := 500.0
const DEFAULT_MAX_ITERATIONS := 200

var graph_data := {
	"id" : "",
	"nodes" : {},
	"edges" : {}
	}

var graphs := []

var graph_mode := 0
var CloudNodeScene = preload("res://ui/3delements/ElementCloudNode3D.tscn")
var ConnectionLineScene = preload("res://ui/3delements/ElementConnectionLine3D.tscn")
var root_node : Object = null
var is_removed := false
var is_active := true
var update_visuals := true

var node_group : Spatial = null
var line_group : Spatial = null

var total_elements := 1
var stream_index := 0
var stream_index_mod := 10


func _ready():
	add_node_layout()
	connect("hovering_node", self, "hovering_node")
	connect("show_connected_nodes", self, "show_connected_nodes")

var rot := 0.0

func _process(delta):
	if Input.is_action_pressed("ui_page_up"):
		rot += delta*36
	elif Input.is_action_pressed("ui_page_down"):
		rot -= delta*36
	$Center.rotation_degrees.y = rot


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


func add_node(_data:Dictionary) -> CloudNode:
	var new_cloud_node = CloudNode.new()
	new_cloud_node.id = _data.id
	new_cloud_node.reported = _data.reported
	new_cloud_node.kind = _data.reported.kind
	new_cloud_node.data = _data
	
	new_cloud_node.scene = CloudNodeScene.instance()
	new_cloud_node.scene.parent_graph = self
	new_cloud_node.scene.cloud_node = new_cloud_node
	node_group.add_child(new_cloud_node.scene)
	new_cloud_node.scene.translation = get_random_pos()
	
	return new_cloud_node


func get_random_pos() -> Vector3:
	var random_vec2 = Vector2(randf()*2000, 0).rotated(randf()*TAU)
	return Vector3(random_vec2.x, random_vec2.y, rand_range(-30, 30))


func add_edge(_data:Dictionary) -> CloudEdge:
	var new_edge = CloudEdge.new()
	new_edge.from = graph_data.nodes[_data.from]
	new_edge.to = graph_data.nodes[_data.to]
	
	var new_edge_line = ConnectionLineScene.instance()
	new_edge.line = new_edge_line
	line_group.add_child(new_edge_line)
	
	return new_edge


func clear_graph( graph_id:= "" ):
	graph_data = {
		"id" : graph_id,
		"nodes" : {},
		"edges" : {}
		}


func start_streaming( graph_id:String ):
	clear_graph( graph_id )
	stream_index = 0
	_e.emit_signal("loading_start")
	_e.emit_signal("loading", 0, "Creating visual elements" )
#	node_group.modulate.a = 0.05


func end_streaming():
	if root_node == null:
		root_node = graph_data.nodes[ graph_data.nodes.keys()[0] ].scene
	
	var total_descendants := 0.0
	var descendants_values := []
	for node in graph_data.nodes.values():
		if "metadata" in node.data and "descendant_count" in node.data.metadata and node.kind == "aws_account" or node.kind == "gcp_project":
			var node_descendant_count = node.data.metadata.descendant_count
			descendants_values.append(node_descendant_count)
			total_descendants += node_descendant_count
	
	var largest_descendant_value = descendants_values.max()
	
	for node in graph_data.nodes.values():
		if "metadata" in node.data and "descendant_count" in node.data.metadata:
			node.scene.descendant_scale = node.data.metadata.descendant_count / largest_descendant_value
	
	emit_signal("graph_created")
	_g.msg( "Visual elements done ... rendering" )
	_e.emit_signal("loading", 1, "Creating visual elements" )
	_e.emit_signal("loading_done")
	_e.emit_signal("nodes_changed")
	update_connection_lines()
	center_diagram()


func add_streamed_object( data : Dictionary ):
	if "id" in data:
		graph_data.nodes[data.id] = add_node(data)
		
		if data.reported.kind == "graph_root":
			root_node = graph_data.nodes[data.id].scene
			
		if stream_index % stream_index_mod == 0:
			_e.emit_signal("loading", float(stream_index) / float(total_elements), "Creating visual elements" )
			_g.msg( "Creating visual elements: {0}/{1}".format([stream_index, total_elements]) )
			yield(get_tree(), "idle_frame")
		stream_index += 1
	else:
		# For SFDP creation
		graph_data.nodes[data.from].connections.append( graph_data.nodes[data.to] )
		graph_data.nodes[data.to].connections.append( graph_data.nodes[data.from] )
		
		# For connection lines
		graph_data.edges[ graph_data.edges.size() ] = add_edge(data)


func create_graph_raw(raw_data : Dictionary, total_nodes:int):
	_e.emit_signal("loading", 0, "Creating visual elements" )
#	node_group.modulate.a = 0.05
	
	var index := 0
	var index_mod = int( max( float(raw_data.size() ) / 100.0, 1) )
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
			
			if data.reported.kind == "graph_root":
				root_node = graph_data.nodes[data.id].scene
		else:
			# For SFDP creation
			graph_data.nodes[data.from].connections.append( graph_data.nodes[data.to] )
			graph_data.nodes[data.to].connections.append( graph_data.nodes[data.from] )
			
			# For connection lines
			graph_data.edges[index] = add_edge(data)
			
	if root_node == null:
		root_node = graph_data.nodes[ graph_data.nodes.keys()[0] ].scene
	
#	node_group.modulate.a = 1
	emit_signal("graph_created")
	_g.msg( "Visual elements done ... rendering" )
	_e.emit_signal("loading", 1, "Creating visual elements" )
	_e.emit_signal("loading_done")


func update_connection_lines() -> void:
	for connection in graph_data.edges.values():
		connection.line.global_transform.origin = connection.from.scene.global_transform.origin
		connection.line.look_at(connection.to.scene.global_transform.origin, Vector3(0,-1,0))
		connection.line.scale.z = (connection.to.scene.global_transform.origin - connection.line.global_transform.origin).length()


func center_diagram():
	$Center/Graph.translation = -root_node.translation


func remove_graph():
	is_removed = true
	disconnect("hovering_node", self, "hovering_node")
	disconnect("show_connected_nodes", self, "show_connected_nodes")
	queue_free()


func layout_graph(graph_node_positions := {}) -> void:
	if graph_node_positions.empty():
		for node in graph_data.nodes.values():
			node.scene.translation = get_random_pos()
			node.scene.random_pos = node.scene.translation
	
	update_connection_lines()
	center_diagram()


func graph_calc_layout():
	center_diagram()
	arrange(DEFAULT_DAMPING, DEFAULT_SPRING_LENGTH, DEFAULT_MAX_ITERATIONS, true)


func calc_repulsion_force_pos(node_a_pos, node_b_pos):
	var force = -REPULSION_CONSTANT / node_a_pos.distance_to(node_b_pos)
	return node_a_pos.direction_to(node_b_pos) * force


func calc_attraction_force_pos(node_a_pos, node_b_pos, spring_length):
	var force = ATTRACTION_CONSTANT * max( ( node_a_pos.distance_to(node_b_pos)) - spring_length, 0)
	return node_a_pos.direction_to(node_b_pos) * force


# Arrange the graph using Spring Electric Algorithm
# returning the nodes positions
func arrange(damping, spring_length, max_iterations, deterministic := false, refine := false):
	var benchmark_start = OS.get_ticks_usec()
	if !deterministic:
		randomize()
	
	var stop_count = 0
	var iterations = 0
	var total_displacement_threshold : float = graph_data.nodes.size()*2 if !refine else 5.0
	#var total_displacement_threshold := 0.01
	
	while true:
		var total_displacement := 0.0
		
		for node in graph_data.nodes.values():
			var current_node_position = node.scene.global_transform.origin
			var net_force = Vector3.ZERO
			
			for other_node in graph_data.nodes.values():
				if node == other_node:
					continue
				
				var other_node_pos = other_node.scene.global_transform.origin
				
				if !other_node in node.connections:
					if current_node_position.distance_to(other_node_pos) < MAX_DISTANCE:
						net_force += calc_repulsion_force_pos( current_node_position, other_node_pos ) * other_node.scene.descendant_scale
				else:
					var attr = calc_attraction_force_pos( current_node_position, other_node_pos, spring_length * node.scene.descendant_scale )
					net_force += attr
			
			node.velocity_3d = ((node.velocity_3d + net_force) * damping * GRAPH_MOVE_SPEED) #.clamped( MAX_DISPLACE )
			damping *= 0.9999999
			node.scene.global_transform.origin += node.velocity_3d
			total_displacement += node.velocity_3d.length()
		
		iterations += 1
		if total_displacement < total_displacement_threshold:
			stop_count += 1
		if stop_count > 10:
			break
		if iterations > max_iterations:
			break
		
		if update_visuals:
			center_diagram()
			update_connection_lines()
		yield(get_tree(), "idle_frame")
		
	center_diagram()
	update_connection_lines()
	
	var saved_node_positions := {}
	for node in graph_data.nodes.values():
		saved_node_positions[node.id] = var2str(node.scene.global_transform.origin)
		node.scene.graph_pos = node.scene.global_transform.origin
	
	var benchmark_end = OS.get_ticks_usec()
	var benchmark_time = (benchmark_end - benchmark_start)/1000000.0
	prints("Time to calculate {0} iterations: {1}".format([iterations-1, benchmark_time]))
	
	emit_signal("order_done", saved_node_positions)
