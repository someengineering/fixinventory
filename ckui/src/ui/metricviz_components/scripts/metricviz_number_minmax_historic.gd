extends Control

export var descr_name := "Total Instances"
export var value_pre := ""
export var value_post := ""
export var descr_add_low := ""
export var descr_add_high := ""
export var value := 100.0
export var show_percentage := "%"
var real_size := Vector2.ZERO

onready var metric_label = $MarginContainer/CenterContainer/HBoxContainer/MetricLabel
onready var progress = $MarginContainer/CenterContainer/Scaler/TextureProgress

func _ready():
	$DescriptionLabel.text = descr_name
	
	if descr_add_low != "":
		$MarginContainer/HBoxContainer/DescrLabel.show()
		$MarginContainer/HBoxContainer/DescrLabel.text = descr_add_low +" "+ show_percentage
	if descr_add_high != "":
		$MarginContainer/HBoxContainer/DescrLabel2.show()
		$MarginContainer/HBoxContainer/DescrLabel2.text = descr_add_high +" "+ show_percentage
	
	
	$MarginContainer/CenterContainer/HBoxContainer/MetricLabelPercent.visible = show_percentage != ""
	$MarginContainer/CenterContainer/HBoxContainer/MetricLabelPercent.text = show_percentage
	
	progress.min_value = float(descr_add_low)
	progress.max_value = float(descr_add_high)
	
	yield(get_tree(), "idle_frame")
	var tex_size = progress.texture_under.get_size().x
	real_size = $MarginContainer.rect_size
	$MarginContainer.rect_min_size.y = real_size.x
	$MarginContainer/CenterContainer/Scaler.scale = Vector2.ONE * (real_size.x/tex_size)
	$MarginContainer/CenterContainer/Control/Marker.scale = Vector2.ONE * (real_size.x/tex_size)


func play_anim():
	$Tween.interpolate_method(self, "count_up", 0, value, 0.4, Tween.TRANS_QUAD, Tween.EASE_OUT)
	$Tween.start()


func count_up(value):
	var text = str(stepify(value, 0.1))
	metric_label.text = text
	progress.value = stepify(value, 0.1)
	$MarginContainer/CenterContainer/Control/Marker.rotation_degrees = range_lerp(stepify(value, 0.1), progress.min_value, progress.max_value, -224, 45)
