extends Node2D

var cloud_node_icon = preload("res://ui/elements/Element_CloudNode.tscn")

onready var line_group = $LineGroup
onready var node_group = $NodeGroup


func _ready():
	_g.connect("load_nodes", self, "read_data")
	_e.connect("hovering_node", self, "hovering_node")
	_e.connect("show_connected_nodes", self, "show_connected_nodes")

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
	var graph_node_positions = Utils.load_json(_g.GRAPH_NODE_JSON_PATH)
	if graph_node_positions.empty():
		for node in _g.nodes.values():
			node.icon.position = Vector2(rand_range(1000, 5760-1000), rand_range(550, 3240-550)) + Vector2(-2880, -1630)
	else:
		for node in _g.nodes.values():
			node.icon.position = str2var(graph_node_positions[node.id])


func hovering_node(node_id, power) -> void:
	for connection in _g.connections.values():
		if connection.to.id == node_id or connection.from.id == node_id:
			var line_color = Color(5,3,1,1) if connection.to.id == node_id else Color(3,4,5,1)
			connection.line.self_modulate = lerp(Color.white, line_color*1.5, power)
