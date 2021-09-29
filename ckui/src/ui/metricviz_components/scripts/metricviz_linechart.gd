extends Control

enum {DETAIL, TOTAL}

export var cloud_type := 0
export var descr_name := "Total Instances"

var is_active := false

var data := []
var plot_visual_data := {}
var values_total := {}
var bar_colors := [Color("#f7b731"), Color("#20bf6b"), Color("#0fb9b1"), Color("#fa8231")]
var current_power := 1.0
var power := 0.0
var uv_size := 1.0
var view = TOTAL

var earliest_date := 0.0
var plot_count := 0

var plot_size := Vector2(300.0, 100.0)
var plot_scale := Vector2(0.0005, 1.0)

onready var attacher = $MarginContainer/Background/MarginContainer/Pos/Attacher
onready var size_container = $MarginContainer/Background/MarginContainer
onready var stamp_line = $MarginContainer/Background/MarginContainer/Pos/Attacher/SelectedTimeStampLine
onready var info_label = $Info/InfoLabel

var current_line_id := -1


func set_plot_size() -> void:
	plot_size = size_container.rect_size - Vector2(10,10)
	$MarginContainer/MetricNameLabel.text = descr_name
	show_total()


func set_data( _data : Array ) -> void:
	if _data.empty():
		return
	
	data = _data
	
	# get earliest date and pre-fill accumulated values
	earliest_date = 0
	values_total = {}
	for data_values in data:
		for value in data_values.values:
			if earliest_date == 0:
				earliest_date = value[0]
			elif value[0] < earliest_date:
				earliest_date = value[0]
				
			# pre-fill accumulated values
			if !values_total.has( value[0] ):
				values_total[ value[0] ] = 0.0
	
	create_plot()
	setup_labels()
	show_detail()
	yield(get_tree(), "idle_frame")
	yield(get_tree(), "idle_frame")
	set_plot_size()
	_on_Background_mouse_exited()


func play_anim():
	$AnimTween.interpolate_property($MarginContainer/Background, "modulate:a", 0, 1, 0.5, Tween.TRANS_SINE, Tween.EASE_OUT)
	attacher.modulate.a = 0
	$AnimTween.interpolate_property(attacher, "modulate", Color.transparent, Color(1.5,1.5,1.5,1), 0.15, Tween.TRANS_SINE, Tween.EASE_OUT)
	$AnimTween.interpolate_property(attacher, "modulate", Color(1.5,1.5,1.5,1), Color.white, 0.5, Tween.TRANS_SINE, Tween.EASE_OUT, 0.15)
	$AnimTween.start()
	_on_Background_mouse_exited()


func setup_labels():
	var date_from_to = Utils.to_date_unix( values_total.keys()[0] ) + " - " + Utils.to_date_unix( values_total.keys()[-1] )
	$MarginContainer/MetricNameLabel/MetricDateRangeLabel.text = date_from_to


func show_total() -> void:
	if view == TOTAL or values_total.empty():
		return
		
	show_only(-1)
	view = TOTAL
	
	var biggest_value := 0.0
	for v in values_total.values():
		if v >= biggest_value:
			biggest_value = v
	
	var last_value = values_total.keys()[-1]
	var data_size = Vector2(last_value - earliest_date, biggest_value)
	plot_scale = (plot_size / data_size )
	
	var line = plot_visual_data.keys()[-1]
	var poly = plot_visual_data[line].poly
	var positions = plot_visual_data[line].points
	var polygon : PoolVector2Array
	var polygon_uvs : PoolVector2Array
	var new_line_data = []
	
	poly.modulate = Color.from_hsv(0.5, 1, 1.0, 1)
	line.modulate = poly.modulate.lightened(0.4)
	
	for i in positions.size():
		new_line_data.append( positions[i]*plot_scale)
		line.set_point_position(i, line.get_point_position(i)*plot_scale)
		polygon.append( new_line_data[i] )
		var uv_x = (uv_size/positions.size()) * i
		polygon_uvs.append( Vector2(uv_x, uv_size-( abs(new_line_data[i].y / plot_size.y)*uv_size ) ) )
		
	polygon.append_array( [Vector2(plot_size.x, 0), Vector2(0, 0)] )
	polygon_uvs.append_array( [Vector2(uv_size, uv_size), Vector2(0, uv_size)] )
	
	line.points = new_line_data
	poly.set_polygon( polygon )
	poly.uv = polygon_uvs


func show_detail() -> void:
	if view == DETAIL or values_total.empty():
		return
		
	show_all()
	view = DETAIL
	
	# set plot scale
	var biggest_value := 0.0
	for v in values_total.values():
		if v >= biggest_value:
			biggest_value = v
	
	var last_value = values_total.keys()[-1]
	var data_size = Vector2(last_value - earliest_date, biggest_value)
	plot_scale = (plot_size / data_size)
	
	# rescale lines and polygons
	var lines = Array(plot_visual_data.keys())
	var lines_amount = lines.size()
	for i in lines_amount:
		var line = lines[i]
		var line_points_amount = line.points.size()
		var curr_data = plot_visual_data[ line ]
		var positions = curr_data.points
		var poly : Polygon2D = curr_data.poly
		var polygon : PoolVector2Array
		var polygon_uvs : PoolVector2Array
		var new_line_data : Array = []
		
		var color_cycle = ((1.0/lines_amount) * i) * 0.1
		poly.modulate = Color.from_hsv(0.6 - color_cycle, 1, 1.0, 1)
		line.modulate = poly.modulate.lightened(0.4)
		
		if i == 0:
			polygon = [ ]
			polygon_uvs = [ ]
			
			for l in line_points_amount:
				new_line_data.append( (positions[l] * plot_scale) )
				line.set_point_position(l, line.get_point_position(l)*plot_scale )
				polygon.append( new_line_data[l] )
				var uv_x = (uv_size/line_points_amount) * l
				polygon_uvs.append( Vector2(uv_x, uv_size-(abs(new_line_data[l].y / plot_size.y)*uv_size) ) )
			
			polygon.append_array( [Vector2(plot_size.x, 0), Vector2(0, 0)] )
			polygon_uvs.append_array( [Vector2(-uv_size, 0), Vector2(0, 0)] )
		else:
			var last_line = lines[i-1]

			polygon = [ ]
			polygon_uvs = [ ]
			
			for l in line_points_amount:
				new_line_data.append( (positions[l] * plot_scale) )
				line.set_point_position(l, line.get_point_position(l)*plot_scale)
				polygon.append( new_line_data[l] )
				var uv_x = (uv_size/line_points_amount) * l
				polygon_uvs.append( Vector2(uv_x, uv_size - (abs(new_line_data[l].y / plot_size.y)*uv_size) ) )
			
			# add the reverse points ( the bottom part )
			for l in line_points_amount:
				polygon.append( last_line.points[-l-1] + Vector2(0, +1) )
				var uv_x = (uv_size/line_points_amount) * abs(l-(line_points_amount-1))
				polygon_uvs.append( Vector2(uv_x, uv_size - (abs(last_line.points[-l-1].y / plot_size.y)*uv_size) ) )
		
		line.points = new_line_data
		poly.set_polygon( polygon )
		poly.uv = polygon_uvs


func create_plot(id := -1):
	var values_total_keys = Array(values_total.keys())
	var data_id := 0
	for d in data:
		if id != -1 and data_id != id:
			data_id += 1
			continue
		# create line
		var new_line = $Line2D.duplicate()
		attacher.add_child(new_line)
		new_line.show()
		
		# create poly
		var new_poly = $Polygon2D.duplicate()
		attacher.add_child(new_poly)
		new_poly.show()
		new_poly.material = new_poly.material.duplicate()
		
		plot_visual_data[new_line] = { "metrics" : d.metrics, "values" : d.values, "poly" : new_poly }
		var points : Array
		
		for i in values_total.size():
			var new_point : Vector2
			
			for value in d.values:
				if value[0] == values_total_keys[i]:
					values_total[ value[0] ] += float( value[1] )
					new_point = Vector2( ( value[0]-earliest_date ), -float( values_total[ value[0] ] ))
				else:
					new_point = Vector2( ( values_total_keys[i]-earliest_date ), -float( values_total[ values_total_keys[i] ] ))
			points.append(new_point)
			
		plot_visual_data[new_line]["points"] = points
		new_line.points = points
		data_id += 1
	show_total()


func show_only(id:int):
	id = wrapi(id, -1, plot_visual_data.size())
	var line_data = Array(plot_visual_data.keys())[ id ]
	var i = 0
	$ShowHideTween.remove_all()
	for line in plot_visual_data.keys():
		i += 1
		if line != line_data:
			$ShowHideTween.interpolate_property(line, "self_modulate:a", 1, 0, 0.3, Tween.TRANS_SINE, Tween.EASE_OUT, i*0.01)
			$ShowHideTween.interpolate_property(plot_visual_data[line].poly, "self_modulate:a", 1, 0, 0.3, Tween.TRANS_SINE, Tween.EASE_OUT, i*0.01)
		else:
			line.show()
			plot_visual_data[line].poly.show()
	$ShowHideTween.start()


func show_all():
	var lines : Array = Array(plot_visual_data.keys())
	$ShowHideTween.remove_all()
	for i in lines.size():
		if i == 0:
			continue
		var line = lines[-i-1]
		var poly = plot_visual_data[lines[-i-1]].poly
		line.self_modulate.a = 0
		poly.self_modulate.a = 0
		$ShowHideTween.interpolate_property(line, "self_modulate:a", 0, 1, 0.15, Tween.TRANS_SINE, Tween.EASE_OUT, 0.1+(i*0.01))
		$ShowHideTween.interpolate_property(poly, "self_modulate:a", 0, 1, 0.15, Tween.TRANS_SINE, Tween.EASE_OUT, 0.1+(i*0.01))
		$ShowHideTween.interpolate_property(line, "scale:y", 0, 1, 0.12, Tween.TRANS_ELASTIC, Tween.EASE_OUT, 0.1+(i*0.01))
		$ShowHideTween.interpolate_property(poly, "scale:y", 0, 1, 0.12, Tween.TRANS_ELASTIC, Tween.EASE_OUT, 0.1+(i*0.01))
		line.show()
		poly.show()
	$ShowHideTween.start()


func _on_ShowHideTween_tween_completed(object, _key):
	if object.self_modulate.a == 0:
		object.hide()


func _on_ColorRect_gui_input(event):
	if is_active and InputMap.event_is_action(event, "zoom_in"):
		print("ZOOM")
	
	if is_active and event is InputEventMouseMotion: 
		show_detail()
		var closest_dist := -1.0
		var closest_curve : Object = null
		var closest_pos : Vector2
		var mouse_pos = get_global_mouse_position()
		var values_total_amount = values_total.size()-1
		var values_total_y_pos = Array( values_total.values() )
		var x_id = clamp(round( ((mouse_pos - rect_global_position).x / plot_size.x) * values_total_amount ), 0, values_total_amount)
		
		var value_pos = Vector2(( (x_id) / values_total_amount ) * plot_size.x, -values_total_y_pos[ min(x_id, values_total_amount)] * plot_scale.y)
		
		stamp_line.show()
		stamp_line.position.x = value_pos.x
		stamp_line.points[0].y = value_pos.y
		stamp_line.get_node("Dot").position.y = value_pos.y
		
		$Info.show()
		var y_pos = $MarginContainer/Background/MarginContainer/Pos/Spacer.rect_global_position.y
		$Info.global_position = Vector2(stamp_line.global_position.x, y_pos)
		$Info/InfoLine.points[1].y = plot_size.y + value_pos.y
		
		
		var label_pos = ($Info.global_position + info_label.rect_size)
		if label_pos.x > 1920:
			info_label.rect_position.x = -16-info_label.rect_size.x
			$Info/Background.rect_position.x = -24-info_label.rect_size.x
		else:
			info_label.rect_position.x = 16
			$Info/Background.rect_position.x = 8
			
		if label_pos.y > 1080:
			info_label.rect_position.y = -info_label.rect_size.y
		else:
			info_label.rect_position.y = 0
			
		
		var current_time = values_total.keys()[x_id]
		var current_value_info : String = "Timestamp: " + Utils.to_date_unix(current_time) + "\n\n"
		var plot_visual_data_values = Array( plot_visual_data.values() )
		var current_value_data : Array
		for i in plot_visual_data_values.size():
			var current_value = 0.0
			for v in plot_visual_data_values[i].values:
				if v[0] == current_time:
					current_value = v[1]
			current_value_data.append( [stepify(float(current_value), 0.1), " :: " + str(plot_visual_data_values[i].metrics.account) + " [ " + str(plot_visual_data_values[i].metrics.cloud) + " ]\n" ] )
		current_value_data.sort_custom(self, "sort_descending")
		
		for i in current_value_data:
			if i[0] == 0:
				continue
			current_value_info += str( i[0] ) + str(i[1])
				
		info_label.text = current_value_info
		$Info/Background.rect_min_size = info_label.rect_size + Vector2(10,10)


func _on_Background_mouse_exited():
	for line in plot_visual_data.keys():
		show_total()
		$Info.hide()
		stamp_line.hide()
		plot_visual_data[line].modulate = Color.white


static func sort_descending(a, b):
		if a[0] > b[0]:
			return true
		return false
