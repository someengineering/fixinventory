extends Popup


func _on_CancelButton_pressed():
	popup_close()
	hide()


func _on_OkButton_pressed():
	popup_ok()
	hide()


func popup_close():
	pass


func popup_ok():
	pass
