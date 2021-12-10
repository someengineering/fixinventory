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


func _ready():
	_on_Timer_timeout()
	_e.connect("load_nodes", self, "popup_show")


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
			output.text = TEXT_FILEFOUND.format([str(stepify(file_size / 1000000, 0.01))])
			ok_btn.show()
		else:
			output.text = TEXT_NOFILE
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
	emit_signal("load_file")


func _on_ExampleDataButton_pressed():
	_g.use_example_data = true
	emit_signal("use_example_data")
	popup_close()


func _on_Timer_timeout():
	set_file_found(check_for_graph_dump())


func _on_ApiModeButton_pressed():
	popup_close()
	_e.emit_signal("connect_popup")
