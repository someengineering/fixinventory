extends Control

const DEFAULT_MSG = "Show the current operation as a query/CLI"

onready var msg_line = $Background/LineEdit
onready var msg_tween = $NewMsgTween

func _ready():
	_e.connect("msg", self, "update_status_display")


func update_status_display( content:String ):
	msg_line.text = content
	msg_line.modulate.a = 1.0
	msg_tween.remove_all()
	msg_tween.interpolate_property(msg_line, "modulate:a", 1, 0.3, 0.2, Tween.TRANS_QUART, Tween.EASE_OUT, 1.5)
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
	msg_line.text = DEFAULT_MSG


func _input(event):
	if event.is_action_pressed("Fullscreen"):
		_on_FullscreenButton_pressed()


func _on_FullscreenButton_pressed():
	if OS.get_name()=="HTML5":
		_g.maximized_window = !_g.maximized_window
		OS.set_window_maximized( _g.maximized_window )
	else:
		OS.window_fullscreen = !OS.window_fullscreen
