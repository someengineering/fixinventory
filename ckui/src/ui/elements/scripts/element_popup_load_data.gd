extends Popup

signal load_file
signal use_example_data

const filters = []

const TEXT_NOFILE = "data/graph.dump.json NOT found!\nYou can continue with generated example data or place the file in the data/ folder inside the project."
const TEXT_FILEFOUND = "data/graph.dump.json found ({0}MB)!"

var file_found := false setget set_file_found
var file_size := 0.0

onready var output = $Margin/MarginContainer/Content/VBoxContainer/Output
onready var ok_btn = $Margin/MarginContainer/PopupButtons/OkButton
onready var grid = $Margin/MarginContainer/Content/VBoxContainer/GridContainer


func _ready():
	_on_Timer_timeout()
	_e.connect("load_nodes", self, "popup_show")


func create_filters():
	var file = File.new()
	var filters := []

	if file.file_exists(_g.GRAPH_DUMP_JSON_PATH):
		file.open(_g.GRAPH_DUMP_JSON_PATH, file.READ)
		while !file.eof_reached():
			var line = file.get_line()
			if line == "":
				continue

			var next_line = parse_json(line)
			if "reported" in next_line:
				if !next_line.reported.kind in filters:
					filters.append(next_line.reported.kind)
		file.close()

	for filter in filters:
		var new_checkbox = $Margin/MarginContainer/Content/VBoxContainer/CheckBox.duplicate()
		new_checkbox.text = filter
		new_checkbox.name = filter
		new_checkbox.show()
		grid.add_child(new_checkbox)


func check_for_graph_dump() -> bool:
	var file = File.new()
	if file.file_exists(_g.GRAPH_DUMP_JSON_PATH):
		file.open(_g.GRAPH_DUMP_JSON_PATH, file.READ)
		file_size = file.get_len()
		file.close()
		return true
	file_size = 0.0
	return false


func set_file_found(value: bool):
	if value != file_found:
		file_found = value
		if file_found:
			create_filters()
			output.text = TEXT_FILEFOUND.format([str(stepify(file_size / 1000000, 0.01))])
			$Margin/MarginContainer/Content/VBoxContainer/FilterButtons.show()
			$Margin/MarginContainer/Content/VBoxContainer/GridContainer.show()
			ok_btn.show()
		else:
			output.text = TEXT_NOFILE
			$Margin/MarginContainer/Content/VBoxContainer/FilterButtons.hide()
			$Margin/MarginContainer/Content/VBoxContainer/GridContainer.hide()
			ok_btn.hide()


func _on_CancelButton_pressed():
	popup_close()


func _on_OkButton_pressed():
	popup_ok()
	popup_close()


func popup_show():
	_g.popup = true
	show()


func popup_close():
	_g.popup = false
	hide()


func popup_ok():
	$Timer.stop()
	_g.popup = false
	var filters := []
	for i in grid.get_children():
		if i.pressed:
			filters.append(i.text)
	emit_signal("load_file", filters)


func _on_ExampleDataButton_pressed():
	_g.use_example_data = true
	emit_signal("use_example_data", [])
	popup_close()


func _on_Timer_timeout():
	set_file_found(check_for_graph_dump())


func _on_AllButton_pressed():
	for i in grid.get_children():
		i.pressed = true


func _on_NoneButton_pressed():
	for i in grid.get_children():
		i.pressed = false


func _on_ApiModeButton_pressed():
	popup_close()
	_e.emit_signal("connect_popup")
