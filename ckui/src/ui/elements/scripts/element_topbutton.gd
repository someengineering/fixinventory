extends ToolButton

export var max_width := 145.0

var active := false setget set_active


func set_active(value: bool):
	if active != value:
		active = value
		if active:
			$Tween.interpolate_property(self, "rect_min_size:x", 40, 40+max_width, 0.6, Tween.TRANS_QUART, Tween.EASE_OUT)
			$Tween.interpolate_property($HBoxContainer/Label, "rect_min_size:x", 0, max_width, 0.6, Tween.TRANS_QUART, Tween.EASE_OUT)
			$Tween.interpolate_property($HBoxContainer/TextureRect, "modulate", Color.white, Color(1.6,1.6,1.6,1), 0.6, Tween.TRANS_QUART, Tween.EASE_OUT)
			$Tween.start()
		else:
			$Tween.interpolate_property(self, "rect_min_size:x", rect_min_size.x, 40, 0.6, Tween.TRANS_QUART, Tween.EASE_OUT)
			$Tween.interpolate_property($HBoxContainer/Label, "rect_min_size:x", $HBoxContainer/Label.rect_min_size.x, 0, 0.6, Tween.TRANS_QUART, Tween.EASE_OUT)
			$Tween.interpolate_property($HBoxContainer/TextureRect, "modulate", $HBoxContainer/TextureRect.modulate, Color.white, 0.6, Tween.TRANS_QUART, Tween.EASE_OUT)
			$Tween.start()
