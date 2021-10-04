extends Node
class_name CloudEdge

var from : CloudNode = null
var to : CloudNode = null
var line : Line2D = null
var color := Color(0.7,0.9,1,0.1)

func clone(original : CloudEdge):
	color = original.color
	from = original.from
	to = original.to
