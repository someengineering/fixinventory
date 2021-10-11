extends Reference
class_name CloudNode

var id := ""
var kind := ""
var reported := {}
var icon : Object
var to := []
var from := []

var velocity : Vector2
var next_pos : Vector2

func clone(original : CloudNode):
	id = original.id
	kind = original.kind
	reported = original.reported.duplicate(true)
