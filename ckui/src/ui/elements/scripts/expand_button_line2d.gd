extends Button

var expand := false setget set_expand

onready var ico = $ExpandIcon

func _on_ExpandButton_mouse_entered():
	ico.modulate = Color(1.5,1.5,1.5,1.0)


func _on_ExpandButton_mouse_exited():
	ico.modulate = Color(1.0,1.0,1.0,0.5)

func set_expand( value:bool ):
	expand = value
	ico.scale.y = -1 if value else 1
