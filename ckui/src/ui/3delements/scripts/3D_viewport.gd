extends ViewportContainer


func _ready():
	get_tree().get_root().connect("size_changed", self, "resize_viewports")


func resize_viewports():
	var new_size = get_viewport().size
	$Viewport.set_size_override(true, Vector2(1920,1080))
	$Viewport.size = new_size
