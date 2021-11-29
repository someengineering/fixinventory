extends Spatial

var scanned := 0.0
var is_scanned := false
var is_selected := false setget set_is_selected
var cloud_node : CloudNode = null setget set_cloud_node
var random_pos := Vector3.ZERO
var graph_pos := Vector3.ZERO
var parent_graph : Object = null
var descendant_scale := 1.0 setget set_descendant_scale
var treemap : Object = null


func _ready() -> void:
#	parent_graph.connect("show_node", self, "show_detail")
#	parent_graph.connect("hide_nodes", self, "hide_detail")
	_e.connect("change_cam_zoom_3d", self, "change_cam_zoom_3d")
	_e.connect("graph_spaceship", self, "update_spaceship_mode")
	set_hover_power(0)
	
	var node_name_full = cloud_node.reported.name
	var node_name_short = node_name_full
	var node_name_lenght = node_name_full.length()
	if node_name_lenght > 16:
		node_name_short = node_name_short.left(8) + "..." + node_name_short.right(node_name_lenght-6)
	_e.emit_signal("request_label", node_name_full, self)


func deliver_label(_image):
	var tex = ImageTexture.new()
	tex.create_from_image(_image)
	$Label.material_override.set_shader_param("texture_albedo", tex)


func change_cam_zoom_3d(zoom:float):
	$Label.scale = Vector3.ONE * zoom * 12


func set_descendant_scale(_value:float):
	pass


func update_spaceship_mode():
	pass


func _process(_delta) -> void:
	pass


func scanning(_delta) -> void:
	pass


func set_cloud_node(value:CloudNode) -> void:
	cloud_node = value


func set_node_type(_value:String) -> void:
	pass

func set_hovering(_value:bool) -> void:
	pass

func set_is_selected(value:bool) -> void:
	is_selected = value


func set_hover_power(_value:float) -> void:
	pass


func show_detail(node_id):
	if node_id != cloud_node.id:
		return
	pass


func hide_detail():
	pass


func _on_Area_input_event(_camera, event, _position, _normal, _shape_idx):
	if event is InputEventMouseButton and event.pressed:
		# left click
		if event.button_index == BUTTON_LEFT:
			_e.emit_signal("go_to_graph_node_3d", cloud_node.id, parent_graph)

		#right click
		elif event.button_index == BUTTON_RIGHT:
			pass
