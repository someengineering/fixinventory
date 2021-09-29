extends Sprite

var blur_power := 0.0

func _ready():
	set_blur(blur_power)

func set_blur(value:float):
	blur_power = value
	modulate = lerp(Color.white, Color(0.6,0.6,0.6,1.0), blur_power)
	material.set_shader_param("power", blur_power*4)
