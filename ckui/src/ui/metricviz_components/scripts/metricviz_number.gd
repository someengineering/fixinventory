extends Control

export var descr_name := "Total Instances"
export var value_pre := ""
export var value_post := ""
export var value := 100.0
export var is_co_2 := false

onready var metric_label = $VBox/MarginContainer/CenterContainer/HBoxContainer/MetricLabel

func _ready():
	$VBox/DescriptionLabel.text = descr_name
	if value_pre != "":
		$VBox/MarginContainer/CenterContainer/HBoxContainer/MetricLabelPre.show()
		$VBox/MarginContainer/CenterContainer/HBoxContainer/MetricLabelPre.text = str(value_pre)
	if value_post != "":
		$VBox/MarginContainer/CenterContainer/HBoxContainer/MetricLabelPost.show()
		$VBox/MarginContainer/CenterContainer/HBoxContainer/MetricLabelPost.text = str(value_post)
	
	yield(get_tree(), "idle_frame")
	if is_co_2:
		$VBox/MarginContainer/CenterContainer/HBoxContainer/MetricLabelPost/Leaf.show()
		$VBox/MarginContainer/Background.modulate = Color(0.5, 2, 0.1, 1.0)


func play_anim():
	$Tween.interpolate_method(self, "count_up", 0, value, 0.4, Tween.TRANS_QUAD, Tween.EASE_OUT)
	if is_co_2:
		$Tween.interpolate_property($VBox/MarginContainer/CenterContainer/HBoxContainer/MetricLabelPost/Leaf, "scale", Vector2.ZERO, Vector2.ONE*0.111, 0.6, Tween.TRANS_QUAD, Tween.EASE_IN_OUT)
		$Tween.interpolate_property($VBox/MarginContainer/CenterContainer/HBoxContainer/MetricLabelPost/Leaf, "rotation", PI/2, 0, 0.6, Tween.TRANS_QUAD, Tween.EASE_IN_OUT)
	$Tween.start()


func count_up(_value):
	metric_label.text = str(round(_value))
