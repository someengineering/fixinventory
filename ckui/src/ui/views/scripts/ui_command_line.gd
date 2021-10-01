extends Control


func _on_ButtonSpaceship_pressed():
	_e.emit_signal("graph_spaceship")


func _on_ButtonRandomize_pressed():
	_e.emit_signal("graph_randomize")


func _on_ButtonOrder_pressed():
	_e.emit_signal("graph_order")
