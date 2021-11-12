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
	_e.connect("change_cam_zoom", self, "change_cam_zoom")
	_e.connect("graph_spaceship", self, "update_spaceship_mode")
	set_hover_power(0)

func change_cam_zoom(zoom:Vector2):
	pass


func set_descendant_scale(value:float):
	pass


func update_spaceship_mode():
	pass


func _process(delta) -> void:
	pass


func scanning(delta) -> void:
	pass


func set_cloud_node(value:CloudNode) -> void:
	cloud_node = value


func set_node_type(value:String) -> void:
	pass

func set_hovering(value:bool) -> void:
	pass

func set_is_selected(value:bool) -> void:
	is_selected = value


func set_hover_power(value:float) -> void:
	pass


func show_detail(node_id):
	if node_id != cloud_node.id:
		return
	pass


func hide_detail():
	pass

