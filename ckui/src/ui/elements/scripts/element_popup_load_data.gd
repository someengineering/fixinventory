extends Popup

signal ok

const FILTERS = [
	"graph_root",
	"cloud",
	"aws_account",
	"aws_region",
	"aws_account",
	"aws_ec2_instance_type",
	"aws_ec2_instance_quota",
	"aws_ec2_instance",
	"aws_ec2_keypair",
	"aws_ec2_volume_type",
	"aws_ec2_volume",
	"aws_ec2_snapshot",
	"aws_ec2_subnet",
	"aws_ec2_elastic_ip",
	"aws_vpc",
	"aws_vpc_quota",
	"aws_s3_bucket",
	"aws_s3_bucket_quota",
	"aws_elb",
	"aws_alb",
	"aws_alb_target_group",
	"aws_elb_quota",
	"aws_alb_quota",
	"aws_ec2_internet_gateway",
	"aws_ec2_nat_gateway",
	"aws_ec2_internet_gateway_quota",
	"aws_ec2_security_group",
	"aws_ec2_route_table",
	"aws_vpc_peering_connection",
	"aws_vpc_endpoint",
	"aws_ec2_network_acl",
	"aws_ec2_network_interface",
	"aws_rds_instance",
	"aws_iam_group",
	"aws_iam_role",
	"aws_iam_policy",
	"aws_iam_instance_profile",
	"aws_iam_access_key",
	"aws_iam_server_certificate",
	"aws_iam_server_certificate_quota",
	"aws_cloudformation_stack",
	"aws_eks_cluster",
	"aws_eks_nodegroup",
	"aws_autoscaling_group",
	"aws_cloudwatch_alarm"
	]

const TEXT_NOFILE = "data/graph.dump.json NOT found!\nYou can continue with generated example data or place the file in the data/ folder inside the project."
const TEXT_FILEFOUND = "data/graph.dump.json found ({0}MB)!"

var file_found := false setget set_file_found
var file_size := 0.0

onready var output = $Margin/MarginContainer/Content/VBoxContainer/Output
onready var ok_btn = $Margin/MarginContainer/PopupButtons/OkButton
onready var grid = $Margin/MarginContainer/Content/VBoxContainer/GridContainer


func _ready():
	_on_Timer_timeout()
	for filter in FILTERS:
		var new_checkbox = $Margin/MarginContainer/Content/VBoxContainer/CheckBox.duplicate()
		new_checkbox.text = filter
		new_checkbox.name = filter
		new_checkbox.show()
		grid.add_child(new_checkbox)
	_e.connect("load_nodes", self, "popup_show")
	

func check_for_graph_dump() -> bool:
	var file = File.new()
	if file.file_exists(_g.GRAPH_DUMP_JSON_PATH):
		file.open(_g.GRAPH_DUMP_JSON_PATH, file.READ)
		file_size = file.get_len()
		file.close()
		return true
	file_size = 0.0
	return false


func set_file_found(value:bool):
	if value != file_found:
		file_found = value
		if file_found:
			output.text = TEXT_FILEFOUND.format([ str(stepify(file_size/1000000, 0.01)) ])
			$Margin/MarginContainer/Content/VBoxContainer/FilterButtons.show()
			$Margin/MarginContainer/Content/VBoxContainer/GridContainer.show()
			ok_btn.show()
		else:
			output.text = TEXT_NOFILE
			$Margin/MarginContainer/Content/VBoxContainer/FilterButtons.hide()
			$Margin/MarginContainer/Content/VBoxContainer/GridContainer.hide()
			ok_btn.hide()


func _on_CancelButton_pressed():
	popup_close()
	hide()


func _on_OkButton_pressed():
	popup_ok()
	hide()


func popup_show():
	_g.popup = true
	show()


func popup_close():
	_g.popup = false


func popup_ok():
	$Timer.stop()
	_g.popup = false
	var filters := []
	for i in grid.get_children():
		if i.pressed:
			filters.append( i.text )
	emit_signal("ok", filters)


func _on_ExampleDataButton_pressed():
	_g.use_example_data = true
	_on_OkButton_pressed()


func _on_Timer_timeout():
	set_file_found( check_for_graph_dump() )


func _on_AllButton_pressed():
	for i in grid.get_children():
		i.pressed = true


func _on_NoneButton_pressed():
	for i in grid.get_children():
		i.pressed = false
