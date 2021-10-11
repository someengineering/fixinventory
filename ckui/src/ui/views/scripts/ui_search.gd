extends Control

onready var line_edit = $SearchContainer/Background/MarginContainer/LineEdit

var nodes := {}

onready var cloud_results = $ResultContainer/Results/HBoxContainer/CloudResults/Items
onready var query_results = $ResultContainer/Results/HBoxContainer/QueryResults/Items

func _ready():
	_e.connect("nodes_changed", self, "set_local_nodes")

func grab_focus():
	$ResultContainer.hide()
	line_edit.grab_focus()
	line_edit.text = ""
	clear_search()


func set_local_nodes():
	nodes = _g.main_graph.graph_data.nodes.duplicate()


func clear_search():
	for c in cloud_results.get_children():
		c.disconnect("pressed", self, "result_node_pressed")
		c.queue_free()
	for c in query_results.get_children():
		c.disconnect("pressed", self, "result_query_pressed")
		c.queue_free()


func _on_LineEdit_text_changed(new_text):
	clear_search()
	yield(get_tree(), "idle_frame")
	
	var search_string = new_text.to_lower()
	var has_node_result := false
	var has_query_result := false
	
	for node in nodes.values():
		if search_string.to_lower() in node.reported.name.to_lower() and cloud_results.get_child_count() < 30:
			has_node_result = true
			var new_item = $ResultContainer/Results/ItemButtonRow.duplicate()
			new_item.get_node("Content/Name").text = node.reported.kind
			new_item.get_node("Content/Detail").text = node.reported.name
			new_item.connect("pressed", self, "result_node_pressed", [node.id])
			new_item.show()
			cloud_results.add_child(new_item)
	
	var query_keys = Array( _g.queries.keys() )
	for i in _g.queries.size():
		var query = _g.queries[ query_keys[i] ]
		var querycontent = str(query.short_name + query.description).to_lower()
		if search_string in querycontent and query_results.get_child_count() < 30:
			has_query_result = true
			var new_item = $ResultContainer/Results/ItemButtonRow.duplicate()
			new_item.get_node("Content/Name").text = query.short_name
			new_item.get_node("Content/Detail").text = query.description
			new_item.connect("pressed", self, "result_query_pressed", [ query_keys[i] ] )
			new_item.show()
			query_results.add_child(new_item)
	
	$ResultContainer/Results/HBoxContainer/CloudResults.visible = has_node_result
	$ResultContainer/Results/HBoxContainer/QueryResults.visible = has_query_result
	$ResultContainer.visible = has_query_result or has_node_result

func result_node_pressed(node_id):
	_e.emit_signal("go_to_graph_node", node_id, _g.main_graph)

func result_query_pressed(query_id):
	_e.emit_signal("load_query", query_id)
