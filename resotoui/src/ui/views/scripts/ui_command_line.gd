extends Control

const DEFAULT_MSG = "Show the current operation as a query/CLI"

var console_open := false

onready var msg_line = $Background/LineEdit
onready var msg_tween = $NewMsgTween
onready var console = $ConsoleBackground/Console

var console_history := []
var console_history_current_id := 0


func _ready():
	_e.connect("msg", self, "update_status_display")
	console.text = ""


func update_status_display(content: String):
	if console_open:
		return
	msg_line.text = content
	msg_tween.remove_all()
	msg_tween.interpolate_property(
		msg_line,
		"modulate",
		Color.white * 1.5,
		Color.white,
		0.2,
		Tween.TRANS_QUART,
		Tween.EASE_OUT,
		2.5
	)
	msg_tween.start()


func _on_ButtonSpaceship_pressed():
	if _g.popup:
		return
	_e.emit_signal("graph_spaceship")


func _on_ButtonRandomize_pressed():
	if _g.popup:
		return
	_e.emit_signal("graph_randomize")


func _on_ButtonOrder_pressed():
	if _g.popup:
		return
	_e.emit_signal("graph_order")


func _on_NewMsgTween_tween_all_completed():
	if console_open:
		return
	msg_line.text = ""


func _input(event):
	if event.is_action_pressed("Fullscreen"):
		_on_FullscreenButton_pressed()
	elif event.is_action_pressed("ui_cancel") and console_open:
		_on_ExpandButton_pressed()
		msg_line.text = ""


func _on_FullscreenButton_pressed():
	if OS.get_name() == "HTML5":
		_g.maximized_window = !_g.maximized_window
		OS.set_window_maximized(_g.maximized_window)
	else:
		OS.window_fullscreen = !OS.window_fullscreen


func _on_ExpandButton_pressed():
	console_open = !console_open
	$ConsoleBackground.visible = console_open
	$ExpandButton.expand = console_open
	msg_line.editable = console_open


func _on_ButtonClear_pressed():
	console.text = ""


func _on_LineEdit_gui_input(event):
	if !console_open and event is InputEventMouseButton and event.pressed:
		_on_ExpandButton_pressed()

	if (
		console_open
		and (event.is_action("ui_up") or event.is_action("ui_down"))
		and console_history.size() > 0
		and event.pressed
	):
		if event.is_action("ui_up"):
			console_history_current_id = wrapi(
				console_history_current_id + 1, 0, console_history.size()
			)
		else:
			console_history_current_id = wrapi(
				console_history_current_id - 1, 0, console_history.size()
			)
		msg_line.text = console_history[console_history_current_id]
		msg_line.caret_position = msg_line.text.length()


func new_api_request():
	_g.api.connect("api_response", self, "api_response")
	_g.api.connect("api_response_finished", self, "api_response_finished")


func api_response(chunk: String):
	console.text += chunk
	console.scroll_vertical = INF


func api_response_finished():
	console.text += "\n\n"
	_g.api.disconnect("api_response", self, "api_response")
	_g.api.disconnect("api_response_finished", self, "api_response_finished")


func _on_LineEdit_text_entered(new_text):
	console_history.append(new_text)
	msg_line.text = ""
	console.text += new_text + "\n"
	if _g.api.connected:
		new_api_request()
		var url: String = "/cli/execute?graph=" + _g.main_graph.graph_data.id
		yield(get_tree(), "idle_frame")
		yield(get_tree(), "idle_frame")
		_e.emit_signal("api_request", HTTPClient.METHOD_POST, url, new_text)
	else:
		console.text += "Not connected.\n\n"
