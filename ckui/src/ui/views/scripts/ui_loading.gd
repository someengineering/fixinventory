extends Control


onready var tween = $LoadingTween


func _ready():
	_e.connect("loading_start", self, "loading_start")
	_e.connect("loading", self, "update_loading_status")
	_e.connect("loading_done", self, "loading_done")

func update_loading_status( loading:float, text:String ):
	$"MetricViz-NumberMinMaxHistoric".set_value( loading * 100, text )


func loading_start():
	modulate.a = 1
	show()


func loading_done():
	tween.remove_all()
	tween.interpolate_property(self, "modulate:a", modulate.a, 0, 0.5, Tween.TRANS_QUAD, Tween.EASE_OUT, 0.3)
	tween.start()


func _on_LoadingTween_tween_all_completed():
	hide()
