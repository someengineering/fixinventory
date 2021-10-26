extends ToolButton

var hovering := false
var hover_power := 0.0
var speed := 15.0

onready var label = $CenterContainer/ButtonLabel
onready var edges = $Background/Extra

func _ready():
	$CenterContainer/ButtonLabel.rect_pivot_offset.x = $CenterContainer/ButtonLabel.rect_size.x/2


func _process(delta) -> void:
	if (hovering and hover_power < 1):
		set_hover_power( min(hover_power + delta * speed, 1.0) )
	elif (!hovering and hover_power > 0):
		set_hover_power( max(hover_power - delta * (speed * 0.3), 0.0) )


func _on_GenericButton_mouse_entered() -> void:
	set_hovering(true)


func _on_GenericButton_mouse_exited() -> void:
	set_hovering(false)


func set_hovering(value:bool) -> void:
	if hovering != value:
		hovering = value


func set_hover_power(value:float) -> void:
	hover_power = value
	var eased_hover_power = ease(hover_power, -2.0)
	label.add_constant_override("shadow_offset_y", eased_hover_power * 10 )
	label.rect_scale = Vector2.ONE + ( Vector2.ONE * eased_hover_power * 0.02 )
	modulate = lerp( Color.white, Color(1.1, 1.4, 1.4, 1.0), eased_hover_power )
	edges.rect_scale.y = range_lerp(eased_hover_power, 0, 1, 1, 0.9)
