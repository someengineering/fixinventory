extends Node2D

var scanned := 0.0
var is_scanned := false
var is_selected := false setget set_is_selected
var cloud_node : CloudNode = null setget set_cloud_node
var random_pos := Vector2.ZERO
var graph_pos := Vector2.ZERO

onready var marker = $Marker
onready var reveal = $Reveal

func _ready() -> void:
	_e.connect("show_node", self, "show_detail")
	_e.connect("hide_nodes", self, "hide_detail")
#
#	if _g.spaceship_mode:
#		$ScannerBar.show()
#		$LabelKind.modulate.a = 0
#		$LabelName.modulate.a = 0
#		$ScannerBar.modulate.a = 0
#	else:
#		$ScannerBar.queue_free()
	set_hover_power(0)


func _process(delta) -> void:
	if (hovering and hover_power < 1):
		hover_power = min(hover_power + delta * speed, 1.0)
	elif (!hovering and hover_power > 0):
		set_hover_power( max(hover_power - delta * (speed * 0.3), 0.0) )
	if hovering:
		set_hover_power(hover_power)


func scanning(delta) -> void:
	if is_scanned:
		return
	if scanned >= 3:
		is_scanned = true
		reveal.interpolate_property($LabelKind, "modulate:a", 0, 1, 1, Tween.TRANS_SINE, Tween.EASE_OUT)
		reveal.interpolate_property($ScannerBar, "modulate:a", 1, 0, 0.3, Tween.TRANS_SINE, Tween.EASE_OUT)
		reveal.interpolate_property($LabelName, "modulate:a", 0, 1, 1, Tween.TRANS_SINE, Tween.EASE_OUT, 0.4)
		reveal.start()
		$Area2D.set_collision_layer_bit(1, false)
	elif scanned <= 0:
		reveal.interpolate_property($ScannerBar, "modulate:a", 0, 1, 0.3, Tween.TRANS_SINE, Tween.EASE_OUT)
		reveal.start()
	scanned += delta
	$ScannerBar.value = scanned


func set_cloud_node(value:CloudNode) -> void:
	cloud_node = value
	$LabelName.text = cloud_node.reported.name
	$LabelKind.text = cloud_node.reported.kind
	set_node_type(cloud_node.reported.kind)


func set_node_type(value:String) -> void:
	if value == "graph_root":
		scale = Vector2.ONE*3
	elif value == "cloud":
		scale = Vector2.ONE*2.5
	elif value == "aws_account":
		scale = Vector2.ONE*2.0
	elif value == "aws_region":
		scale = Vector2.ONE*1.5
	elif value == "aws_s3_bucket":
		scale = Vector2.ONE*0.7
		#modulate.a = 0.7
	elif value == "aws_iam_policy" or value == "aws_iam_instance_profile" or value == "aws_ec2_security_group" or value == "aws_ec2_keypair" or value == "aws_ec2_snapshot":
		scale = Vector2.ONE*0.6
		#modulate.a = 0.6
	elif value == "aws_iam_role" or value == "aws_ec2_subnet" or value == "aws_ec2_route_table" or value == "aws_iam_server_certificate":
		scale = Vector2.ONE*0.5
		#modulate.a = 0.5
	else:
		scale = Vector2.ONE


func _on_Area2D_input_event(_viewport, event, _shape_idx) -> void:
	if event is InputEventMouseButton and !event.pressed:
		# left click
		if event.button_index == 1:
			_e.emit_signal("go_to_graph_node", cloud_node.id)

		#right click
		elif event.button_index == 2:
			pass


# Animation related things

var hovering := false
var hover_power := 0.0
var speed := 15.0


func _on_Area2D_mouse_entered():
	set_hovering(true)


func _on_Area2D_mouse_exited():
	if !is_selected:
		set_hovering(false)


func set_hovering(value:bool) -> void:
	if hovering != value:
		hovering = value
		if hovering:
			_e.emit_signal("show_connected_nodes", cloud_node.id)
		else:
			_e.emit_signal("hide_nodes")


func set_is_selected(value:bool) -> void:
	is_selected = value
	if !is_selected:
		set_hovering(false)
	else:
		_e.emit_signal("show_connected_nodes", cloud_node.id)


func set_hover_power(value:float) -> void:
	hover_power = value
	var eased_hover_power = ease(hover_power, -2.0)
	marker.scale = lerp(Vector2(0.5,0.5), Vector2.ONE, eased_hover_power)
	marker.modulate = lerp( Color.transparent, Color.white, eased_hover_power )
	marker.width = range_lerp(eased_hover_power, 0, 1, 1, 0.5)
	marker.rotation = eased_hover_power * PI * 0.5
	_e.emit_signal("hovering_node", cloud_node.id, eased_hover_power)


func show_detail(node_id):
	if node_id != cloud_node.id:
		return
	reveal.remove_all()
	reveal.interpolate_property($LabelName, "modulate:a", $LabelName.modulate.a, 1, 0.1, Tween.TRANS_QUART, Tween.EASE_OUT)
	reveal.interpolate_property($LabelKind, "rect_position:y", $LabelKind.rect_position.y, -33, 0.1, Tween.TRANS_QUART, Tween.EASE_OUT)
	reveal.start()


func hide_detail():
	reveal.remove_all()
	reveal.interpolate_property($LabelName, "modulate:a", $LabelName.modulate.a, 0, 0.1, Tween.TRANS_QUART, Tween.EASE_OUT)
	reveal.interpolate_property($LabelKind, "rect_position:y", $LabelKind.rect_position.y, -11, 0.1, Tween.TRANS_QUART, Tween.EASE_OUT)
	reveal.start()
