extends Reference
class_name CloudEdge

var from: CloudNode = null
var to: CloudNode = null
var line: Object = null
var color := Color(0.7, 0.9, 1, 0.5)
var colors_temp := [Color(0.7, 0.9, 1, 0.5), Color(1.0, 0.5, 0.1, 0.5)]


func clone(original: CloudEdge):
	color = original.color
	from = original.from
	to = original.to
