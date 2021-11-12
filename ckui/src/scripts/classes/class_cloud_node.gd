extends Reference
class_name CloudNode

var id := ""
var kind := ""
var reported := {}
var data := {}
var scene : Object
var connections := []
var velocity : Vector2
var velocity_3d : Vector3

func clone(original : CloudNode):
	id = original.id
	kind = original.kind
	reported = original.reported.duplicate(true)
