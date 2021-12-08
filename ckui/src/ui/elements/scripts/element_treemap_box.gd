extends MarginContainer

var element_color := Color.white
var label := ""
var value := 0.0
var final_size := Vector2.ZERO

onready var text_label = $Center/C/Z/Label


func _ready():
	text_label.text = label + "\n" + str(value)
	$Button.modulate = element_color
	if final_size.x < 100 or final_size.y < 100:
		text_label.hide()
	yield(VisualServer, "frame_post_draw")
	text_label.rect_position = -text_label.rect_size / 2


func _on_Button_mouse_entered():
	text_label.rect_position = -text_label.rect_size / 2
