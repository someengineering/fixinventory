extends Node2D

var DAMPING = 0.99
var ROT_DAMPING = 0.95
var THRUST = 0.5
var ROT_THRUST = 0.005

var velocity := Vector2.ZERO
var rot_velocity := 0.0

var scanning_nodes := []
var ship_active := false

func _ready():
	if _g.ee:
		ship_active = true
	var ship_scale = scale.x
	THRUST *= ship_scale
	

func _physics_process(delta):
	if !ship_active:
		return
	velocity *= DAMPING
	rot_velocity *= ROT_DAMPING
	
	var rotation_input = -Input.get_action_strength("ui_left") + Input.get_action_strength("ui_right")
	var thrust_input = Input.get_action_strength("ui_up")
	
	if rotation_input != 0:
		rot_velocity += ROT_THRUST * sign(rotation_input)
	
	if thrust_input != 0:
		velocity += Vector2.UP.rotated(rotation) * THRUST
		$Engine.show()
		$Engine.scale = Vector2(rand_range(0.6,1.2), rand_range(0.6,1.2))
		$Engine_Particles.emitting = true
	
	$Engine.visible = thrust_input != 0
	$Engine_Particles.emitting = thrust_input != 0
	
	rotation += rot_velocity
	position += velocity
	
	for i in scanning_nodes:
		i.scanning(delta)


func _on_Scanner_area_entered(area):
	if !scanning_nodes.has( area.get_parent() ):
		scanning_nodes.append( area.get_parent() )


func _on_Scanner_area_exited(area):
	if scanning_nodes.has( area.get_parent() ):
		scanning_nodes.erase( area.get_parent() )
