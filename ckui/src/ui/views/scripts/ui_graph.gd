extends Node2D

const GRAPH_DUMP_JSON_PATH = "res://data/graph.dump.json"
const GRAPH_NODE_JSON_PATH := "res://data/graph_node_positions.json"

signal filtering_done

var root_node : Object = null
var mouse_is_pressed := false
var last_drag_pos := Vector2.ZERO
var new_drag_pos := Vector2.ZERO
var is_dragging_cam := false
var drag_sensitivity := 1.0
var drag_power := Vector2.ZERO
var target_node : CloudNode = null
var cam_moving := false
var selected_new_node := false
var original_zoom := Vector2.ONE
var spaceship : Object = null
var Spaceship = preload("res://ui/elements/Element_Spaceship.tscn")
var is_active := true setget set_is_active
var loaded_data_filtered_ids := []

onready var graph_cam = $GraphCam
onready var cam_tween = $CamMoveTween
onready var graph_bg = $BG/BG

export (NodePath) onready var main_ui = get_node(main_ui)

func _ready():
	_g.main_graph = $GraphView
	_g.main_graph.connect("order_done", self, "save_order")
	_e.connect("load_nodes", self, "read_data")
	_e.connect("graph_order", self, "main_graph_order")
	_e.connect("graph_randomize", self, "main_graph_rand")
	_e.connect("graph_spaceship", self, "update_spaceship_mode")
	_e.connect("go_to_graph_node", self, "go_to_graph_node")
	_e.connect("nodeinfo_hide", self, "hide_info")
	self.connect("filtering_done", self, "generate_graph")


func set_is_active(value:bool):
	is_active = value
	_g.main_graph.is_active = value


func _process(delta):
	if root_node == null or !is_active:
		return
	
	# move the center of the background gradient in the direction of the root node
	var dist_to_root_node = min(root_node.global_position.distance_to(graph_cam.global_position), 2000)
	var dir_to_root_node = root_node.global_position.direction_to(graph_cam.global_position)
	var zoom_factor = range_lerp(graph_cam.zoom.x, 0.5, 4, 1, 0.1)
	graph_bg.material.set_shader_param("center", -dir_to_root_node * ease(range_lerp(dist_to_root_node, 0, 2000, 0, 1), 0.7) * zoom_factor)


func read_data():
	var file = File.new()
	var new_data := {}
	loaded_data_filtered_ids.clear()
	
	if file.file_exists(GRAPH_DUMP_JSON_PATH) and !_g.use_example_data:
		file.open(GRAPH_DUMP_JSON_PATH, file.READ)
		var file_len : float = float( file.get_len() )
		var update_mod : int = file.get_len() / 500000
		var index := 0
		var benchmark_start = OS.get_ticks_usec()
		_g.msg( "Reading file ..." )
		_e.emit_signal("loading_start")
		_e.emit_signal("loading", 0, "Reading file" )
		yield(get_tree(), "idle_frame")
		var filter_by_kinds := ["graph_root", "cloud", "aws_region", "aws_account"]
		
		while !file.eof_reached():
			var line = file.get_line()
			if line == "":
				index += 1
				continue
			var next_line = parse_json(line)
			if filter_data_on_load(next_line, filter_by_kinds):
				new_data[index] = next_line
			index += 1
			if index % update_mod == 0: 
				_g.msg( "Reading file - line {0}".format([index]) )
				_e.emit_signal("loading", (float( file.get_position() ) / file_len), "Reading file" )
				yield(get_tree(), "idle_frame")
		
		var benchmark_end = OS.get_ticks_usec()
		var benchmark_time = (benchmark_end - benchmark_start)/1000000.0
		
		_e.emit_signal("loading", 1, "Reading file" )
		_g.msg( "Reading file done! {0} Nodes in Graph | Loading time: {1}".format([index, stepify(benchmark_time, 0.01)]) )
		
		file.close()
	else:
		var example_data_file = load("res://scripts/tools/example_data.gd")
		var example_data = example_data_file.new()
		new_data = example_data.graph_data.duplicate()
	
	generate_graph(new_data)
	
	
func generate_graph(filtered_data_result:Dictionary):
	var file = File.new()
	var graph_node_positions := {}
	if file.file_exists(GRAPH_NODE_JSON_PATH) and !_g.use_example_data:
		var new_graph_node_positions = Utils.load_json(GRAPH_NODE_JSON_PATH)
		if typeof(new_graph_node_positions) == TYPE_DICTIONARY:
			graph_node_positions = new_graph_node_positions
	_g.main_graph.create_graph_raw(filtered_data_result, filtered_data_result.size())
	yield(_g.main_graph, "graph_created")
	_g.main_graph.layout_graph(graph_node_positions)
	root_node = _g.main_graph.root_node
	graph_cam.global_position = root_node.global_position
	graph_cam.zoom = Vector2.ONE*0.8
	
	_e.emit_signal("nodes_changed")
	_g.main_graph.emit_signal("hide_nodes")


func filter_data_on_load(element, filter_by_kinds):
	if "id" in element:
		if element.reported.kind in filter_by_kinds:
			loaded_data_filtered_ids.append(element.id)
			return true
	elif element.to in loaded_data_filtered_ids and element.from in loaded_data_filtered_ids:
		return true
	else:
		return false


func main_graph_order():
	_g.main_graph.graph_calc_layout()


func save_order(saved_node_positions):
	Utils.save_json(GRAPH_NODE_JSON_PATH, saved_node_positions)


func main_graph_rand():
	_g.main_graph.graph_rand_layout()


func _physics_process(delta):
	if !is_active:
		return
	mouse_is_pressed = Input.is_action_pressed("left_mouse")
	var is_in_graph = main_ui.state == main_ui.states.GRAPH
	if mouse_is_pressed and !target_node and !selected_new_node and is_in_graph and !_g.spaceship_mode:
		if !is_dragging_cam:
			is_dragging_cam = true
			new_drag_pos = get_viewport().get_mouse_position()
			last_drag_pos = new_drag_pos
		else:
			new_drag_pos = get_viewport().get_mouse_position()
			drag_power = (new_drag_pos-last_drag_pos)
			last_drag_pos = new_drag_pos
	else:
		drag_power *= 50*delta
		is_dragging_cam = false
	graph_cam.position -= drag_power*graph_cam.zoom.x
	
	if is_in_graph:
		if Input.is_action_just_released("zoom_in"):
			graph_cam.zoom = max(graph_cam.zoom.x * 0.95, 0.2) * Vector2.ONE
		elif Input.is_action_just_released("zoom_out"):
			graph_cam.zoom = min(graph_cam.zoom.x * 1.05, 20) * Vector2.ONE
	
	if _g.spaceship_mode:
		graph_cam.global_position = spaceship.global_position


func update_spaceship_mode():
	if _g.spaceship_mode:
		spaceship = Spaceship.instance()
		add_child(spaceship)
		spaceship.global_position = graph_cam.global_position
		spaceship.appear()
		cam_tween.remove_all()
		cam_tween.interpolate_property(graph_cam, "zoom", graph_cam.zoom, Vector2(0.2,0.2), 0.3, Tween.TRANS_QUART, Tween.EASE_IN_OUT)
		cam_tween.start()
	else:
		cam_tween.remove_all()
		cam_tween.interpolate_property(graph_cam, "zoom", graph_cam.zoom, Vector2.ONE, 0.3, Tween.TRANS_QUART, Tween.EASE_IN_OUT)
		cam_tween.start()
		spaceship.vanish()
		spaceship = null


func zoom_out():
	original_zoom = graph_cam.zoom
	cam_tween.remove_all()
	cam_tween.interpolate_property(graph_cam, "zoom", graph_cam.zoom, Vector2.ONE*0.4, 0.7, Tween.TRANS_EXPO, Tween.EASE_OUT)
	cam_tween.start()


func zoom_in():
	cam_tween.remove_all()
	cam_tween.interpolate_property(graph_cam, "zoom", graph_cam.zoom, original_zoom, 0.7, Tween.TRANS_EXPO, Tween.EASE_OUT)
	cam_tween.start()


func go_to_graph_node(node_id, graph) -> void:
	if !is_active or graph != _g.main_graph:
		return
	if target_node != null:
		target_node.icon.is_selected = false
	
	target_node = _g.main_graph.graph_data.nodes[node_id]
	_g.main_graph.emit_signal("hide_nodes")
	_g.main_graph.emit_signal("show_node", node_id)
	
	selected_new_node = true
	$NewNodeSelectionTimer.start()
	var target_pos = target_node.icon.global_position
	var target_zoom = target_node.icon.scale
	var flytime = range_lerp(clamp(target_pos.distance_to(graph_cam.global_position), 100, 1000), 100, 1000, 0.35, 1.5)
	cam_tween.remove_all()
	cam_tween.interpolate_property(graph_cam, "global_position", graph_cam.global_position, target_pos, flytime, Tween.TRANS_QUART, Tween.EASE_IN_OUT)
	cam_tween.interpolate_property(graph_cam, "zoom", graph_cam.zoom, target_zoom*0.5, flytime, Tween.TRANS_QUART, Tween.EASE_IN_OUT)
	cam_tween.start()
	target_node.icon.is_selected = true
	cam_moving = true


func _on_CamMoveTween_tween_all_completed() -> void:
	if target_node != null and cam_moving:
		cam_moving = false
		if !is_active:
			return
		_e.emit_signal("nodeinfo_show", target_node)


func _on_NewNodeSelectionTimer_timeout():
	selected_new_node = false


func _on_MouseDetector_input_event(_viewport, event, _shape_idx):
	if !is_active:
		return
	if event is InputEventMouseButton:
		if !event.pressed and !selected_new_node and target_node != null:
			cam_tween.interpolate_property(graph_cam, "zoom", graph_cam.zoom, Vector2.ONE*0.8, 0.7, Tween.TRANS_EXPO, Tween.EASE_OUT)
			cam_tween.start()
			target_node.icon.is_selected = false
			target_node = null
			cam_moving = false
			_e.emit_signal("nodeinfo_hide")

func hide_info():
	pass
