extends Control

export var descr_name := "Total Instances"
export var value_pre := ""
export var value_post := ""
export var descr_add := ""
export var value := 100.0
export var show_percentage := true
var real_size := Vector2.ZERO

onready var metric_label = $MarginContainer/CenterContainer/HBoxContainer/MetricLabel

func _ready():
	$DescriptionLabel.text = descr_name
	
	if value_pre != "":
		$MarginContainer/CenterContainer/HBoxContainer/MetricLabelPre.show()
		$MarginContainer/CenterContainer/HBoxContainer/MetricLabelPre.text = str(value_pre)
	if value_post != "":
		$MarginContainer/CenterContainer/HBoxContainer/MetricLabelPost.show()
		$MarginContainer/CenterContainer/HBoxContainer/MetricLabelPost.text = str(value_post)
	
	if descr_add != "":
		$MarginContainer/CenterContainer/Control/DescrLabel.show()
		$MarginContainer/CenterContainer/Control/DescrLabel.text = descr_add
	
	
	$MarginContainer/CenterContainer/HBoxContainer/MetricLabelPercent.visible = show_percentage
	
	yield(get_tree(), "idle_frame")
	var tex_size = $MarginContainer/CenterContainer/Scaler/TextureProgress.texture_under.get_size().x
	real_size = $MarginContainer.rect_size
	$MarginContainer.rect_min_size.y = real_size.x
	$MarginContainer/CenterContainer/Scaler.scale = Vector2.ONE * (real_size.x/tex_size)
	$MarginContainer/CenterContainer/Control/Marker.scale = Vector2.ONE * (real_size.x/tex_size)


func play_anim():
	$Tween.interpolate_method(self, "count_up", 0, value, 0.4, Tween.TRANS_QUAD, Tween.EASE_OUT)
	$Tween.start()


func count_up(_value):
	var text = str(round(_value))
	metric_label.text = text
	$MarginContainer/CenterContainer/Scaler/TextureProgress.value = value
	$MarginContainer/CenterContainer/Control/Marker.rotation_degrees = range_lerp(value, 0, 100, -224, 45)
