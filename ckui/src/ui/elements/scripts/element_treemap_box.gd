extends MarginContainer

var element_color := Color.white
var label := ""
var value := 0.0

onready var text_label = $Center/C/Z/Label

func _ready():
	text_label.text = label + "\n" + str(value)
	$Button.modulate = element_color


func _on_Button_mouse_entered():
	text_label.rect_position = -text_label.rect_size/2
	text_label.show()


func _on_Button_mouse_exited():
	text_label.hide()
