extends Node2D

enum states {GRAPH, SEARCH, DASHBOARD, QUERY, BLASTRADIUS, POPUP}

onready var blur = $UI/Blur
onready var ui_graph = $UIGraph
onready var ui_dashboard = $UI/UIDashboard
onready var ui_query = $UI/UIQueryEngine
onready var ui_topbar = $UI/UITopbar
onready var ui_search = $UI/UISearch
onready var ui_blastradius = $UI/UIBlastradius
onready var ui_commandline = $UI/UICommandLine


var state = -1 setget set_state
var old_state = -1


func _ready() -> void:
	_g.interface = self
	# This was used for local testing using JSON files in the /data directory
#	_e.emit_signal("load_nodes")

	# The new default is to connect to ckcore
	_e.emit_signal("connect_popup")
	
	_e.connect("go_to_graph_node", self, "go_to_graph_node")
	_e.connect("graph_spaceship", self, "update_spaceship_mode")
	_e.connect("load_query", self, "load_query")
	_e.connect("show_blastradius", self, "show_blastradius")
	
	ui_dashboard.show()
	ui_dashboard.rect_global_position = Vector2(-1920,0)
	ui_query.show()
	ui_search.modulate.a = 0
	set_state(states.GRAPH)


func _input(event) -> void:
	if _g.spaceship_mode or _g.popup or ui_commandline.console_open:
		return
	if event.is_action_pressed("ui_left"):
		if state == states.GRAPH:
			set_state(states.DASHBOARD)
	elif event.is_action_pressed("ui_right"):
		if state == states.DASHBOARD:
			set_state(states.GRAPH)
		elif state == states.GRAPH:
			set_state(states.QUERY)
	
	elif (state == states.SEARCH or state == states.QUERY) and event.is_action_pressed("ui_cancel"):
		set_state(states.GRAPH)
	
	elif event is InputEventKey and InputMap.event_is_action(event, "search") and event.pressed and state != states.QUERY:
		set_state(states.SEARCH)


func set_state(new_state:int) -> void:
	if new_state == state or _g.spaceship_mode:
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
		_e.emit_signal("nodeinfo_hide")
		var ui_tween = ui_graph.get_node("AnimTween")
		ui_graph.zoom_out()
		ui_graph.is_active = false
		ui_tween.interpolate_method(blur, "set_blur", blur.blur_power, 1, 0.7, Tween.TRANS_QUAD, Tween.EASE_OUT)
		ui_tween.start()
		
	elif state_id == states.BLASTRADIUS:
		ui_blastradius.clear_blastradius()
		ui_blastradius.clear_history()
		var ui_tween = ui_blastradius.get_node("AnimTween")
		ui_tween.interpolate_property(ui_blastradius, "modulate:a", ui_blastradius.modulate.a, 0, 0.3, Tween.TRANS_EXPO, Tween.EASE_OUT)
		ui_tween.start()
		yield(ui_tween, "tween_all_completed")
		ui_blastradius.hide()


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
		ui_graph.is_active = true
		ui_graph.zoom_in()
		ui_tween.interpolate_method(blur, "set_blur", blur.blur_power, 0, 0.7, Tween.TRANS_QUAD, Tween.EASE_OUT)
		ui_tween.start()
	
	elif state_id == states.BLASTRADIUS:
		ui_blastradius.show()
		var ui_tween = ui_blastradius.get_node("AnimTween")
		ui_tween.interpolate_property(ui_blastradius, "modulate:a", ui_blastradius.modulate.a, 1, 0.1, Tween.TRANS_EXPO, Tween.EASE_OUT)
		ui_tween.start()


func show_blastradius(_id) -> void:
	set_state(states.BLASTRADIUS)


func go_to_graph_node(_node_id, graph) -> void:
	if graph != _g.main_graph:
		return
	set_state(states.GRAPH)


func load_query(_query_id) -> void:
	set_state(states.QUERY)


func update_spaceship_mode():
	set_state(states.GRAPH)


func _on_UIBlastradius_close_blast_radius():
	set_state(states.GRAPH)
