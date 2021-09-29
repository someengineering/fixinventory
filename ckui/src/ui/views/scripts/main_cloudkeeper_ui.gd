extends Node2D

enum states {GRAPH, SEARCH, DASHBOARD, QUERY}

onready var blur = $UI/Blur
onready var ui_graph = $Graph
onready var graph_cam = $Graph/GraphCam
onready var ui_dashboard = $UI/UIDashboard
onready var ui_query = $UI/UIQueryEngine
onready var ui_nodeinfo = $UI/UINodeInfo
onready var ui_topbar = $UI/UITopbar
onready var ui_search = $UI/UISearch
onready var cam_tween = $Graph/CamMoveTween

var state = -1 setget set_state
var old_state = -1
var cam_moving := false
var selected_new_node := false
var target_node : CloudNode = null
var mouse_is_pressed := false
var last_drag_pos := Vector2.ZERO
var new_drag_pos := Vector2.ZERO
var is_dragging_cam := false
var drag_sensitivity := 1.0
var drag_power := Vector2.ZERO

func _ready() -> void:
	_g.interface = self
	ui_dashboard.rect_global_position = Vector2(-1920,0)
	graph_cam.zoom = Vector2.ONE*0.8
	ui_search.modulate.a = 0
	_g.emit_signal("load_nodes")
	_e.connect("go_to_graph_node", self, "go_to_graph_node")
	_e.connect("load_query", self, "load_query")
	if _g.ee:
		graph_cam.zoom = Vector2.ONE*0.1
		$Graph/Spaceship.show()
		$Graph/Spaceship/RemoteTransform2D.update_position = true
	else:
		$Graph/Spaceship.queue_free()
	
	set_state(states.GRAPH)
	graph_cam.global_position = _g.nodes[ _g.nodes.keys()[1] ].icon.global_position


func _physics_process(delta):
	mouse_is_pressed = Input.is_action_pressed("left_mouse")
	if mouse_is_pressed and !target_node and !selected_new_node and state == states.GRAPH:
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
	
	if state == states.GRAPH:
		if Input.is_action_just_released("zoom_in"):
			graph_cam.zoom = max(graph_cam.zoom.x * 0.95, 0.3) * Vector2.ONE
		elif Input.is_action_just_released("zoom_out"):
			graph_cam.zoom = min(graph_cam.zoom.x * 1.05, 4) * Vector2.ONE
	


func _input(event) -> void:
	if _g.ee:
		return
	if event.is_action_pressed("ui_left"):
		if state == states.GRAPH:
			set_state(states.DASHBOARD)
#		elif state == states.QUERY:
#			set_state(states.GRAPH)
		
	elif event.is_action_pressed("ui_right"):
		if state == states.DASHBOARD:
			set_state(states.GRAPH)
		elif state == states.GRAPH:
			set_state(states.QUERY)
	
	elif (state == states.SEARCH or state == states.QUERY) and event.is_action_pressed("ui_cancel"):
		set_state(states.GRAPH)
	
	elif event is InputEventKey and event.pressed and state != states.QUERY:
		set_state(states.SEARCH)


func set_state(new_state:int) -> void:
	if new_state == state:
		return
	
	old_state = state
	state = new_state
	ui_topbar.change_button(old_state, new_state)
	
	hide_interface(old_state)
	show_interface(state)


func hide_interface(state_id:int) -> void:
	if state_id == states.DASHBOARD:
		var ui_tween = ui_dashboard.get_node("AnimTween")
		ui_dashboard.deactivate()
		ui_tween.interpolate_property(ui_dashboard, "rect_position", ui_dashboard.rect_position, Vector2(-1920,0), 0.3, Tween.TRANS_EXPO, Tween.EASE_IN)
		ui_tween.start()
		
	elif state_id == states.SEARCH:
		var ui_tween = ui_search.get_node("AnimTween")
		ui_tween.interpolate_property(ui_search, "rect_position:y", ui_search.rect_position.y, ui_search.rect_position.y-40, 0.4, Tween.TRANS_EXPO, Tween.EASE_OUT)
		ui_tween.interpolate_property(ui_search, "modulate:a", ui_search.modulate.a, 0, 0.4, Tween.TRANS_EXPO, Tween.EASE_OUT)
		ui_tween.start()
		yield(ui_tween, "tween_all_completed")
		ui_search.hide()
	
	elif state_id == states.QUERY:
		var ui_tween = ui_query.get_node("AnimTween")
		ui_tween.interpolate_property(ui_query, "rect_position", ui_query.rect_position, Vector2(1920,0), 0.3, Tween.TRANS_EXPO, Tween.EASE_IN)
		ui_tween.start()
		
	elif state_id == states.GRAPH:
		ui_nodeinfo.hide_info()
		var ui_tween = ui_graph.get_node("AnimTween")
		ui_tween.interpolate_property(graph_cam, "zoom", graph_cam.zoom, Vector2.ONE*0.4, 0.7, Tween.TRANS_EXPO, Tween.EASE_OUT)
		ui_tween.interpolate_method(blur, "set_blur", blur.blur_power, 1, 0.7, Tween.TRANS_QUAD, Tween.EASE_OUT)
		ui_tween.start()


func show_interface(state_id:int) -> void:
	if state_id == states.DASHBOARD:
		var ui_tween = ui_dashboard.get_node("AnimTween")
		ui_dashboard.activate()
		ui_tween.interpolate_property(ui_dashboard, "rect_position", ui_dashboard.rect_position, Vector2.ZERO, 0.4, Tween.TRANS_EXPO, Tween.EASE_OUT)
		ui_tween.start()
	
	elif state_id == states.QUERY:
		var ui_tween = ui_query.get_node("AnimTween")
		ui_tween.interpolate_property(ui_query, "rect_position", ui_query.rect_position, Vector2.ZERO, 0.4, Tween.TRANS_EXPO, Tween.EASE_OUT)
		ui_tween.start()
		
	elif state_id == states.SEARCH:
		var ui_tween = ui_search.get_node("AnimTween")
		ui_tween.interpolate_property(ui_search, "rect_position:y", ui_search.rect_position.y-40, 0, 0.4, Tween.TRANS_EXPO, Tween.EASE_OUT, 0.3)
		ui_tween.interpolate_property(ui_search, "modulate:a", ui_search.modulate.a, 1, 0.4, Tween.TRANS_EXPO, Tween.EASE_OUT, 0.3)
		ui_search.show()
		ui_search.grab_focus()
		ui_tween.start()
		
	elif state_id == states.GRAPH:
		var ui_tween = ui_graph.get_node("AnimTween")
		ui_tween.interpolate_property(graph_cam, "zoom", graph_cam.zoom, Vector2.ONE*0.8, 0.7, Tween.TRANS_EXPO, Tween.EASE_OUT)
		ui_tween.interpolate_method(blur, "set_blur", blur.blur_power, 0, 0.7, Tween.TRANS_QUAD, Tween.EASE_OUT)
		ui_tween.start()


func go_to_graph_node(node_id) -> void:
	if target_node != null:
		target_node.icon.is_selected = false
	
	set_state(states.GRAPH)
	ui_nodeinfo.hide_info()
	target_node = _g.nodes[node_id]
	_e.emit_signal("hide_nodes")
	_e.emit_signal("show_node", node_id)
	
	selected_new_node = true
	$Graph/NewNodeSelectionTimer.start()
	var target_pos = target_node.icon.global_position
	var target_zoom = target_node.icon.scale
	var flytime = range_lerp(clamp(target_pos.distance_to(graph_cam.global_position), 100, 1000), 100, 1000, 0.35, 1.5)
	cam_tween.interpolate_property(graph_cam, "global_position", graph_cam.global_position, target_pos, flytime, Tween.TRANS_QUART, Tween.EASE_IN_OUT)
	cam_tween.interpolate_property(graph_cam, "zoom", graph_cam.zoom, target_zoom*0.5, flytime, Tween.TRANS_QUART, Tween.EASE_IN_OUT)
	cam_tween.start()
	target_node.icon.is_selected = true
	cam_moving = true


func load_query(_query_id) -> void:
	set_state(states.QUERY)


func _on_CamMoveTween_tween_all_completed() -> void:
	if target_node != null and cam_moving:
		cam_moving = false
		ui_nodeinfo.show_info(target_node)


func _on_MouseDetector_input_event(_viewport, event, _shape_idx):
	if event is InputEventMouseButton:
		if !event.pressed and !selected_new_node and target_node != null:
			cam_tween.interpolate_property(graph_cam, "zoom", graph_cam.zoom, Vector2.ONE*0.8, 0.7, Tween.TRANS_EXPO, Tween.EASE_OUT)
			cam_tween.start()
			target_node.icon.is_selected = false
			target_node = null
			cam_moving = false
			ui_nodeinfo.hide_info()


func _on_NewNodeSelectionTimer_timeout():
	selected_new_node = false
