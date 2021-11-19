extends Node2D

var viewports := {}
var label_queue := []

func _enter_tree():
	_e.connect("request_label", self, "request_label")

func _ready():
	viewports[$Viewport] = true
	for i in 10:
		var new_viewport = $Viewport.duplicate()
		add_child(new_viewport)
		viewports[new_viewport] = true


func _process(_delta):
	if label_queue.empty():
		return
	fullfil_orders()


func request_label(_string:String, _subscriber:Object):
	# is_done, label text, subscriber
	label_queue.append( [false, _string, _subscriber] )


func fullfil_orders():
	var keys = viewports.keys()
	var label_queue_size = label_queue.size()
	for i in viewports.size():
		if i >= label_queue_size:
			break
		
		var current_viewport = viewports[ keys[i] ]
		if current_viewport and !label_queue[i][0]:
			current_viewport = false
			keys[i].get_node("Label").text = label_queue[i][1]
			(keys[i] as Viewport).render_target_update_mode = Viewport.UPDATE_ONCE
			create_image_from_viewport( keys[i], label_queue[i][2], i )


func create_image_from_viewport(_viewport, _subscriber, _label_queue_id):
	yield(VisualServer, "frame_post_draw")
	(_viewport as Viewport).render_target_clear_mode = Viewport.CLEAR_MODE_ONLY_NEXT_FRAME
	var img = _viewport.get_texture().get_data()
	_subscriber.deliver_label( img )
	#label_queue[_label_queue_id][0] = true
	viewports[_viewport] = true
	label_queue.pop_front()
