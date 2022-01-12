extends Reference
class_name CloudNode

var id := ""
var kind := ""
var data := {}
var scene: Object
var connections := []
var edges_to := []
var edges_from := []
var velocity: Vector2
var velocity_3d: Vector3


func clone(original: CloudNode):
	id = original.id
	kind = original.kind
	data = original.data.duplicate(true)
