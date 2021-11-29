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
const DEFAULT_MAX_ITERATIONS := 20000

# Multithreading variables
var threads_finished_count := 0
var threads := []

var graph_data := {}
var graph_node_groups := {}

var graph_mode := 0
var CloudNodeScene = preload("res://ui/3delements/ElementCloudNode3D.tscn")
var ConnectionLineScene = preload("res://ui/3delements/ElementConnectionLine3D.tscn")
var root_node : Object = null
var is_removed := false
var is_active := true
var update_visuals := false

var node_group : Spatial = null
var line_group : Spatial = null

var total_elements := 1
var stream_index := 0
var stream_index_mod := 10


func _ready():
	threads_prepare(12)
	clear_graph()
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
	line_group.name = "Line_Group"
	line_group.translation.z = -5
	graph.add_child(line_group)
	
	node_group = Spatial.new()
	node_group.name = "Node_Group"
	graph.add_child(node_group)


func add_node(_data:Dictionary, _scene:Object, _parent:Object) -> CloudNode:
	var new_cloud_node = CloudNode.new()
	new_cloud_node.id = _data.id
	new_cloud_node.reported = _data.reported
	new_cloud_node.kind = _data.reported.kind
	new_cloud_node.data = _data
	
	new_cloud_node.scene = _scene
	new_cloud_node.scene.parent_graph = self
	new_cloud_node.scene.cloud_node = new_cloud_node
	_parent.add_child(new_cloud_node.scene)
	new_cloud_node.scene.translation = Utils.get_random_pos_3D()
	
	return new_cloud_node


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


class NodeGroup:
	var node_group_object : Spatial = null
	var nodes_in_group : PoolStringArray = []
	var root_node : Spatial = null
	
	func _init(_parent_node:Spatial, _name:String, _root_node:Spatial):
		node_group_object = Spatial.new()
		node_group_object.name = "Grp_"+_name
		root_node = _root_node
		_parent_node.add_child(node_group_object)
	
	func add(_new_node:String):
		nodes_in_group.append(_new_node)


func add_new_node_group(_name:String, _group_parent:Spatial, _root_node:Spatial):
	if !_name:
		return
	graph_node_groups[_name] = NodeGroup.new(_group_parent, _name, _root_node)


func add_streamed_object( data : Dictionary ):
	if "id" in data:
		create_new_graph_node( data )
			
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


func create_new_graph_node( data : Dictionary ):
	var new_graph_node = CloudNodeScene.instance()
	# Set the default parent for the new CloudNodeScene
	var _parent_node = node_group
	
	if "metadata" in data:
		if "cloud" in data.kinds:
			new_graph_node.name = "Cloud_"+data.reported.name
			add_new_node_group(data.reported.name, new_graph_node, new_graph_node )
			graph_node_groups["root"].add(data.id)
			
		elif "account" in data.kinds:
			new_graph_node.name = "Account_"+data.reported.name
			_parent_node = graph_node_groups[ data.metadata.ancestors.cloud.id ].node_group_object
			add_new_node_group(data.reported.name, new_graph_node, new_graph_node )
			graph_node_groups[ data.metadata.ancestors.cloud.id ].add(data.id)
			
		elif "ancestors" in data.metadata and "account" in data.metadata.ancestors:
			new_graph_node.name = "Region_"+data.reported.name
			_parent_node = graph_node_groups[ data.metadata.ancestors.account.name ].node_group_object
			graph_node_groups[ data.metadata.ancestors.account.name ].add(data.id)
#			
		else:
			new_graph_node.name = "Root_Node"
			add_new_node_group("root", _parent_node, new_graph_node)
			graph_node_groups["root"].add(data.id)
	
	graph_data.nodes[data.id] = add_node(data, new_graph_node, _parent_node)
	
	if data.reported.kind == "graph_root":
		root_node = graph_data.nodes[data.id].scene


func create_graph_raw(raw_data : Dictionary, total_nodes:int):
	_e.emit_signal("loading", 0, "Creating visual elements" )
	
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
			create_new_graph_node( data )
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
			node.scene.translation = Utils.get_random_pos_3D()
			node.scene.random_pos = node.scene.translation
	
	update_connection_lines()
	center_diagram()


func graph_calc_layout():
	center_diagram()
	
	var benchmark_start = OS.get_ticks_usec()
	var total_iterations := 0
	var graph_data_node_keys = graph_data.nodes.keys()
	for group in graph_node_groups.values():
		var new_layout_group = []
		for children in group.nodes_in_group:
			new_layout_group.append( graph_data.nodes[children] )
		total_iterations += arrange(new_layout_group, DEFAULT_DAMPING, DEFAULT_SPRING_LENGTH, DEFAULT_MAX_ITERATIONS, true)
		center_diagram()
		update_connection_lines()
		yield(get_tree(), "idle_frame")
	
	var saved_node_positions := {}
	for node in graph_data.nodes.values():
		saved_node_positions[node.id] = var2str(node.scene.global_transform.origin)
		node.scene.graph_pos = node.scene.global_transform.origin
	
	var benchmark_end = OS.get_ticks_usec()
	var benchmark_time = (benchmark_end - benchmark_start)/1000000.0
	prints("Time to calculate {0} iterations: {1}".format([total_iterations-1, benchmark_time]))
	
	emit_signal("order_done", saved_node_positions)


func threads_prepare(_threads_amount:int):
	for i in _threads_amount:
		threads.append(Thread.new())


func thread_repulsion_start(_thread_id:int, node_a_pos:Vector3, node_b_pos:Vector3):
	var thread_data := [_thread_id, node_a_pos, node_b_pos]
	threads[_thread_id].start(self, "thread_calc_repulsion", thread_data)

func thread_calc_repulsion(_thread_data:Array) -> Vector3:
	call_deferred("_thread_repulsion_repulsion_finished", _thread_data)
	return calc_repulsion_force_pos(_thread_data[1], _thread_data[2])

func _thread_repulsion_repulsion_finished(_thread_data:Array) -> void:
	pass


func calc_repulsion_force_pos(node_a_pos, node_b_pos):
	var force = -REPULSION_CONSTANT / node_a_pos.distance_to(node_b_pos)
	return node_a_pos.direction_to(node_b_pos) * force


func calc_attraction_force_pos(node_a_pos, node_b_pos, spring_length):
	var force = ATTRACTION_CONSTANT * max( ( node_a_pos.distance_to(node_b_pos)) - spring_length, 0)
	return node_a_pos.direction_to(node_b_pos) * force


# Arrange the graph using Spring Electric Algorithm
# returning the nodes positions
func arrange(graph_data_node_array, damping, spring_length, max_iterations, deterministic := false, refine := false):
	if !deterministic:
		randomize()
	
	var stop_count = 0
	var iterations = 0
	var total_displacement_threshold : float = graph_data.nodes.size()*2 if !refine else 5.0
	#var total_displacement_threshold := 0.01
	
	while true:
		var total_displacement := 0.0
		
		for node in graph_data_node_array:
			var current_node_position = node.scene.transform.origin
			var net_force = Vector3.ZERO
			
			for other_node in graph_data_node_array:
				if node == other_node:
					continue
				
				var other_node_pos = other_node.scene.transform.origin
				
				if !other_node in node.connections:
					if current_node_position.distance_to(other_node_pos) < MAX_DISTANCE:
						net_force += calc_repulsion_force_pos( current_node_position, other_node_pos ) * other_node.scene.descendant_scale
				else:
					var attr = calc_attraction_force_pos( current_node_position, other_node_pos, spring_length * node.scene.descendant_scale )
					net_force += attr
			
			node.velocity_3d = ((node.velocity_3d + net_force) * damping * GRAPH_MOVE_SPEED) #.clamped( MAX_DISPLACE )
			damping *= 0.9999999
			node.scene.transform.origin += node.velocity_3d
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
	return iterations


func _exit_tree():
	# Check if threads are still active and if not, wait for them to finish
	for thread in threads:
		if thread.is_active():
			thread.wait_to_finish()
