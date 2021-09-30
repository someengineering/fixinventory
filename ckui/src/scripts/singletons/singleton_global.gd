extends Node

signal nodes_changed
signal load_nodes

var nodes := {}
var connections := {}
var spaceship_mode := false
var interface : Object = null
var use_example_data := false


var queries := {
	0 : { "short_name" : "Unused Load Balancers", "description" : "Finds unused Load Balancers in your cloud.", "query" : 'is(aws_alb) and ctime<"-{0}" and backends==[] with(empty, <-- is(aws_alb_target_group) and target_type=="instance" and ctime<"-{0}" with(empty, <-- is(aws_ec2_instance) and instance_status!="terminated")) <-[0:1]- is(aws_alb_target_group) and target_type=="instance" and ctime<"-{0}"', "dynamic_fields" : ["ctime","7d"] }
}
