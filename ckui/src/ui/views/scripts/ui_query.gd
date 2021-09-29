extends Control

var query = null

onready var edit_field = $EditContainer/Background/HBoxContainer/LineEdit

func _ready():
	_e.connect("load_query", self, "load_query")
	_e.emit_signal("load_query", 0)

func load_query(query_id):
	query = _g.queries[query_id]
	$SearchContainer/Background/HBoxContainer/QueryLabel_Long.text = query.description
	$SearchContainer/Background/HBoxContainer/QueryLabel_Short.text = query.short_name
	
	edit_field.text = query.dynamic_fields[1]
	$EditContainer/Background/HBoxContainer/Propertyname.text = query.dynamic_fields[0]

	$QueryEditor/Background/MarginContainer/LineEdit.text = query.query.format([edit_field.text],"{_}")

func _on_LineEdit_text_changed(new_text):
	$QueryEditor/Background/MarginContainer/LineEdit.text = query.query.format([edit_field.text],"{_}")
