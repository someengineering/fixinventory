extends Node

const GRAPH_DUMP_JSON_PATH = "res://data/graph.dump.json"
const GRAPH_NODE_JSON_PATH := "res://data/graph_node_positions.json"
const PROMETHEUS_METRICS_JSON_PATH = "res://data/prometheus_metrics.json"

var main_graph: Object setget set_main_graph
var spaceship_mode := false
var interface: Object = null
var use_example_data := false
var popup := false
var maximized_window := false
var use_2d_graph := false

var api: Object = null

var queries := {
	0:
	{
		"short_name": "Unused Load Balancers",
		"description": "Finds unused Load Balancers in your cloud.",
		"query":
		'is(aws_alb) and ctime<"-{0}" and backends==[] with(empty, <-- is(aws_alb_target_group) and target_type=="instance" and ctime<"-{0}" with(empty, <-- is(aws_ec2_instance) and instance_status!="terminated")) <-[0:1]- is(aws_alb_target_group) and target_type=="instance" and ctime<"-{0}"',
		"dynamic_fields": ["ctime", "7d"]
	}
}


func _ready():
	_e.connect("graph_spaceship", self, "set_spaceship_mode")


func set_spaceship_mode():
	spaceship_mode = !spaceship_mode


func set_main_graph(value: Object):
	main_graph = value
	_e.emit_signal("nodes_changed")


func msg(content: String):
	_e.emit_signal("msg", content)
	yield(get_tree(), "idle_frame")
