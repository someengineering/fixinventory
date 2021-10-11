extends Node2D

var scanned := 0.0
var is_scanned := false
var is_selected := false setget set_is_selected
var cloud_node : CloudNode = null setget set_cloud_node
var random_pos := Vector2.ZERO
var graph_pos := Vector2.ZERO
var parent_graph : Object = null

onready var marker = $Marker
onready var reveal = $Reveal

onready var label_kind = $Labels/LabelKind
onready var label_name = $Labels/LabelName

func _ready() -> void:
	parent_graph.connect("show_node", self, "show_detail")
	parent_graph.connect("hide_nodes", self, "hide_detail")
	_e.connect("graph_spaceship", self, "update_spaceship_mode")
	label_name.text = cloud_node.reported.name
	label_kind.text = cloud_node.reported.kind
	set_hover_power(0)


func labels_unisize(font_scale := 0.5):
	$Labels.global_scale = Vector2.ONE * font_scale


func update_spaceship_mode():
	if _g.spaceship_mode:
		is_selected = false
		set_hovering(false)
		label_kind.modulate.a = 0
		label_name.modulate.a = 0
		label_kind.rect_position.y = -140
	else:
		$Area2D.set_collision_layer_bit(1, true)
		label_name.modulate.a = 0
		label_kind.rect_position.y = -52
		label_kind.modulate.a = 1
		label_name.percent_visible = 1
		label_kind.percent_visible = 1


func _process(delta) -> void:
	if !_g.spaceship_mode:
		if (hovering and hover_power < 1):
			hover_power = min(hover_power + delta * speed, 1.0)
		elif (!hovering and hover_power > 0):
			set_hover_power( max(hover_power - delta * (speed * 0.3), 0.0) )
		if hovering:
			set_hover_power(hover_power)
	elif hover_power > 0:
		hover_power = 0
		set_hover_power(hover_power)


func scanning(delta) -> void:
	if is_scanned:
		return
	if scanned >= 2:
		is_scanned = true
		$Area2D.set_collision_layer_bit(1, false)
		label_kind.modulate.a = 1
		label_name.modulate.a = 1
		reveal.interpolate_property(self, "modulate", Color(1,2,3,1), Color.white, 1.5, Tween.TRANS_QUART, Tween.EASE_OUT)
		reveal.start()
	elif scanned <= 0:
		reveal.interpolate_property(label_kind, "modulate:a", 0, 0.5, 1, Tween.TRANS_SINE, Tween.EASE_OUT)
		reveal.interpolate_property(label_name, "modulate:a", 0, 0.5, 1, Tween.TRANS_SINE, Tween.EASE_OUT)
		reveal.start()
	scanned += delta
	label_name.percent_visible = clamp(scanned, 1, 2)-1
	label_kind.percent_visible = clamp(scanned, 0, 1)


func set_cloud_node(value:CloudNode) -> void:
	cloud_node = value
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
	if event is InputEventMouseButton and !event.pressed and parent_graph.is_active:
		# left click
		if event.button_index == 1:
			_e.emit_signal("go_to_graph_node", cloud_node.id, parent_graph)

		#right click
		elif event.button_index == 2:
			pass


# Animation related things

var hovering := false
var hover_power := 0.0
var speed := 15.0


func _on_Area2D_mouse_entered():
	if !_g.spaceship_mode and parent_graph.is_active:
		set_hovering(true)


func _on_Area2D_mouse_exited():
	if !is_selected:
		set_hovering(false)


func set_hovering(value:bool) -> void:
	if hovering != value:
		hovering = value
		if hovering:
			parent_graph.emit_signal("show_connected_nodes", cloud_node.id)
		else:
			parent_graph.emit_signal("hide_nodes")


func set_is_selected(value:bool) -> void:
	is_selected = value
	if !is_selected:
		set_hovering(false)
	else:
		parent_graph.emit_signal("show_connected_nodes", cloud_node.id)


func set_hover_power(value:float) -> void:
	hover_power = value
	var eased_hover_power = ease(hover_power, -2.0)
	marker.visible = hover_power > 0
	marker.scale = lerp(Vector2(0.5,0.5), Vector2.ONE, eased_hover_power)
	marker.modulate.a = lerp( 0, 1, eased_hover_power )
	marker.width = range_lerp(eased_hover_power, 0, 1, 1, 0.5)
	marker.rotation = eased_hover_power * PI * 0.5
	parent_graph.emit_signal("hovering_node", cloud_node.id, eased_hover_power)


func show_detail(node_id):
	if node_id != cloud_node.id:
		return
	label_name.show()
	reveal.remove_all()
	reveal.interpolate_property(label_name, "modulate:a", label_name.modulate.a, 1, 0.1, Tween.TRANS_QUART, Tween.EASE_OUT)
	reveal.interpolate_property(label_kind, "rect_position:y", label_kind.rect_position.y, -140, 0.1, Tween.TRANS_QUART, Tween.EASE_OUT)
	reveal.start()


func hide_detail():
	reveal.remove_all()
	reveal.interpolate_property(label_name, "modulate:a", label_name.modulate.a, 0, 0.1, Tween.TRANS_QUART, Tween.EASE_OUT)
	reveal.interpolate_property(label_kind, "rect_position:y", label_kind.rect_position.y, -52, 0.1, Tween.TRANS_QUART, Tween.EASE_OUT)
	reveal.start()


func _on_Reveal_tween_all_completed():
	if label_name.modulate.a < 0.1:
		label_name.hide()
