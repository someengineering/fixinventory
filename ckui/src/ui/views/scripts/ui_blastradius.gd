extends Control

signal close_blast_radius
signal closing_anim_done

var GraphView = preload("res://ui/3delements/Element_GraphView_3D.tscn")
var node_distance := {}
var sort_dict := {}
var blastradius_diameter := 400.0
var graph_view : Object = null
var is_closing := false
var core_node_id := ""
var last_node_id := ""
var api_error := false

onready var tween = $Tween
onready var blast_info = $BlastLabel/BlastNodeInfo

func _ready():
	_e.connect("show_blastradius", self, "show_blastradius")
	_e.connect("go_to_graph_node", self, "go_to_graph_node")


func show_blastradius(node_id) -> void:
	last_node_id = core_node_id
	$BackButton.visible = last_node_id != ""
	core_node_id = node_id
	graph_view = GraphView.instance()
	$UIGraph3DViewport/Viewport.add_child(graph_view)
	var blastradius = get_blastradius_from_selection(node_id)
	print(blastradius)
	graph_view.create_graph_raw(blastradius[0], blastradius[1])
	layout_blastradius()
	graph_view.update_connection_lines()
	graph_view.show_all()
	$BlastLabel/BlastNodeName.text = "Origin: " + _g.main_graph.graph_data.nodes[node_id].reported.name


func layout_blastradius() -> void:
	var keys = graph_view.graph_data.nodes.keys()
	var nodes = graph_view.graph_data.nodes
	var node_amount = keys.size()
	
	var largest_dist := 0
	for i in node_distance.values():
		if i > largest_dist:
			largest_dist = i
	
	sort_dict = {}
	for i in largest_dist+1:
		sort_dict[i] = []
	
	var dist_keys = node_distance.keys()
	for i in sort_dict.keys():
		for d in dist_keys:
			if node_distance[d] == i:
				sort_dict[i].append(d)
	
	# If the blast radius is not including any other nodes
	if node_amount == 1:
		largest_dist = 1
	
	for dist in sort_dict.values():
		var nodes_on_ring = dist.size()
		var i := 0
		for node in dist:
			var node_obj = nodes[ node ]
			var node_dist = node_distance[ node ]
			var new_position = Vector2( (blastradius_diameter/largest_dist) * node_dist, 0).rotated( PI + PI/2 + ((TAU/nodes_on_ring) * i) )
			tween.interpolate_property(node_obj.scene, "position", Vector2.ZERO, new_position, float(node_dist)*0.2, Tween.TRANS_QUINT, Tween.EASE_OUT)
			node_obj.scene.scale = Vector2.ONE * range_lerp( node_dist, 0, largest_dist, 1.5, 0.5)
			node_obj.scene.modulate = Color(1.3, 0.6, 0.6, min(node_obj.scene.scale.x+0.2, 1))
			i += 1
	tween.interpolate_method(self, "update_lines", 0, 1, float(largest_dist)*0.2, Tween.TRANS_QUINT, Tween.EASE_OUT)
	draw_blastradius(Vector2.ZERO, blastradius_diameter+20, node_amount == 1)
	tween.interpolate_property($BlastUIElements, "scale", Vector2.ZERO, Vector2.ONE, float(largest_dist)*0.2, Tween.TRANS_QUINT, Tween.EASE_OUT)
	tween.start()
	
	if node_amount == 1:
		for node in graph_view.graph_data.nodes.values():
			node.scene.modulate = Color.white


func update_lines(_p) -> void:
	graph_view.update_connection_lines()


func draw_blastradius(center, radius, is_green:=false) -> void:
	var resolution = 128
	var points = PoolVector2Array()
	var uvs = PoolVector2Array()

	for i in resolution+1:
		var angle_point = i * (TAU / resolution)
		points.append(center + Vector2(cos(angle_point), sin(angle_point)) * radius)
		uvs.append( Vector2(0.5,0.5) + Vector2(cos(angle_point), sin(angle_point)) )
	
	$BlastUIElements/Polygon2D.polygon = points
	$BlastUIElements/Polygon2D.uv = uvs
	
	
	var largest_dist := 0
	for i in node_distance.values():
		if i > largest_dist:
			largest_dist = i
	
	if is_green:
		largest_dist = 1
		blast_info.text = "Blast radius is clear!"
		$BlastLabel.modulate = Color(0.2, 1.3, 0.5, 1.0)
		$BlastUIElements/Polygon2D.modulate = Color(0.2, 1.3, 0.5, 1.0)
	else:
		blast_info.text = "Nodes in blast radius:\n"
		$BlastLabel.modulate = Color(1.5, 0.3, 0.3, 1.0)
		$BlastUIElements/Polygon2D.modulate = Color(1.0, 0.0, 0.0, 1.0)
	
	
	for i in largest_dist+1:
		if i == 0:
			continue
		var new_line = $BlastUIElements/Line2D.duplicate()
		var new_points = PoolVector2Array()
		for x in resolution+1:
			var angle_point = x * (TAU / resolution)
			new_points.append(center + Vector2(cos(angle_point), sin(angle_point)) * ((radius / largest_dist) * i))
		new_line.points = new_points
		new_line.show()
		new_line.default_color = Color(2, 0.2, 0.2, 1.0) if !is_green else Color(0.2, 1.3, 0.5, 1.0)
		new_line.self_modulate.a = ease((1.0  / (largest_dist)) * i, 3)
		new_line.get_node("Blastlevel").text = str(i) + " edges" if i > 1 else str(i) + " edge"
		if is_green:
			new_line.get_node("Blastlevel").text = ""
		new_line.get_node("Blastlevel").rect_position = new_points[0] + Vector2(5,0)
		new_line.show()
		$BlastUIElements/Instanced.add_child(new_line)
		
		if !is_green:
			blast_info.text += str(sort_dict[i].size()) + " nodes in " + str(i) + " edge radius\n"
	

func get_blastradius_from_selection(node_id):
	var graph_id = "ck"
	var query = "id(" + node_id + ") -[0:]->"
	
	graph_view.start_streaming( graph_id )
	_g.api.connect("api_response", self, "api_response")
	_g.api.connect("api_response_finished", self, "api_response_finished")
	
	var url : String = "/graph/" + graph_id + "/query/graph"
	_e.emit_signal("api_request", HTTPClient.METHOD_POST, url, query)


func api_response( chunk:String ):
	if chunk == "" or chunk == "[" or chunk == "\n]" or chunk == ",\n" or chunk.begins_with("Error:"):
		if chunk.begins_with("Error:"):
			api_error = true
		return
	
	var parse_result : JSONParseResult = JSON.parse( chunk.trim_prefix(",\n") )
	if parse_result.error == OK:
		graph_view.add_streamed_object( parse_result.result )


func api_response_finished():
	_g.api.disconnect("api_response", self, "api_response")
	_g.api.disconnect("api_response_finished", self, "api_response_finished")
	if api_error:
		print("API reported Error!")
		return
	graph_view.end_streaming()
	print("API response finished!")


func merge_cloudgraphs(original:Dictionary, update:Dictionary, iterations:int) -> Dictionary:
	for node in update.nodes.keys():
		if !original.nodes.has(node):
			original.nodes[node] = update.nodes[node]
			node_distance[node] = iterations
	
	for edge in update.edges.keys():
		if !original.edges.has(edge):
			original.edges[edge] = update.edges[edge]
			
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
			new_cloudgraph.edges[edge_key] = CloudEdge.new()
			new_cloudgraph.edges[edge_key].clone( connection )
	
	var nodes = _g.main_graph.graph_data.nodes
	for connection in new_cloudgraph.edges.values():
		var connection_id = connection.to.id
		if nodes.has(connection_id) and connection_id != node_id:
			new_cloudgraph.nodes[connection_id] = CloudNode.new()
			new_cloudgraph.nodes[connection_id].clone( nodes[connection_id] )
	
	return new_cloudgraph


func clear_blastradius() -> void:
	is_closing = true
	var time_to_collapse = 0.1
	tween.interpolate_property($BlastUIElements, "scale", Vector2.ONE, Vector2.ZERO, time_to_collapse*1.5, Tween.TRANS_QUAD, Tween.EASE_OUT)
	tween.interpolate_method(self, "update_lines", 1, 0, time_to_collapse, Tween.TRANS_QUAD, Tween.EASE_OUT)
	for node in graph_view.graph_data.nodes.values():
		tween.interpolate_property(node.scene, "position", node.scene.position, Vector2.ZERO, time_to_collapse, Tween.TRANS_QUAD, Tween.EASE_OUT)
	tween.start()


func _on_CloseButton_pressed() -> void:
	clear_history()
	clear_blastradius()
	emit_signal("close_blast_radius")


func clear_history():
	last_node_id = ""
	core_node_id = ""


func go_to_graph_node(node_id, graph) -> void:
	if graph != graph_view:
		return
	if node_id == core_node_id:
		_e.emit_signal("go_to_graph_node", node_id, _g.main_graph)
	else:
		clear_blastradius()
		yield(self, "closing_anim_done")
		show_blastradius(node_id)


func _on_Tween_tween_all_completed() -> void:
	if !is_closing:
		return
	for i in $BlastUIElements/Instanced.get_children():
		i.queue_free()
	graph_view.remove_graph()
	graph_view = null
	is_closing = false
	emit_signal("closing_anim_done")


func _on_BackButton_pressed():
	go_to_graph_node(last_node_id, graph_view)
