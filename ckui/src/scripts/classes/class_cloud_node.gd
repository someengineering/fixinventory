extends Reference
class_name CloudNode

var id := ""
var kind := ""
var reported := {}
var scene : Object
var connections := []
var velocity : Vector2

func clone(original : CloudNode):
	id = original.id
	kind = original.kind
	reported = original.reported.duplicate(true)
