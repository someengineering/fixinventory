extends Control

const TREEMAP_ELEMENT = preload("res://ui/elements/Element_TreeMap_Box.tscn")

export (Gradient) var gradient
export (Vector2) var treemap_size := Vector2(600,600)

var treemap_size_temp := treemap_size
var datasets := []

var start : int = 0
var end : int = 0
var offset := Vector2.ZERO
var is_vert : bool = aspect_vertical(treemap_size_temp)
var aspect_current : float = 9999999999999.0
var aspect_last : float = 0.0

var fake_data : Dictionary = {
	"df12611ab51a9890888ea5f9a354087ad472a41493950610ddbe9af8042f53c0":1035,
	"D2iQ":8341,
	"gcp-dcos-launch-178319":11677,
	"mesosphere-support":11721,
	"braided-flow-431":11571,
	"eng-mesosphere-dcos":11557,
	"cto-office":11675,
	"kudobuilder":11676,
	"mesosphere-segment":11676,
	"massive-bliss-781":12128,
	"terraform-clusters":11690,
	"maestro-229419":11989,
	"sre-tests":11680,
	"konvoy-gcp-se":11895,
	"mesoscon-demo":11955,
	"pumpkin-246815":11682,
	"eng-ksphere-platform":12864,
	"eng-ksphere-platform-e2e-night":13022,
	"eng-ksphere-platform-e2e":17034,
	"general-cto":492,
	"eng-ksphere-soak":1657,
	"general-services":7012,
	"mesosphere-cops":528,
	"eng-production":3563,
	"eng-ksphere-kommander":2502,
	"mesosphere-team05":436,
	"eng-ksphere-platform2":25775,
	"eng-sre":1040,
	"eng-devprod":3241,
	"eng-playground-alpha":540,
	"mesosphere-team06":838,
	"general-support":1635,
	"eng-mesosphere-osc":5213,
	"eng-audit":447,
	"sales-lead-gen":6991,
	"general-root":542,
	"eng-ksphere-lhub":603,
	"eng-mesosphere-testmatrix":561,
	"eng-ksphere-devx":1678,
	"eng-mesosphere-marathon":704,
	"eng-ksphere-lab":1067,
	"eng-lhub-airf":14760,
	"eng-scaletesting":1452,
	"mesosphere-protoss-scaletesting":1763,
	"200319803118":0,
	"eng-mesosphere-qualification":3913,
	"eng-mesosphere-storage":552,
	"eng-mesosphere-soak":1215,
	"eng-lhub-ci":765,
	"mesosphere-dev":10025,
	"eng-mesosphere-dcos2":4166,
	"eng-ksphere-insights":442,
	"general-marketing":448,
	"sales-se-demo":1095,
	"mesosphere-team09":1476,
	"eng-mesosphere-ds":22248,
	"eng-ksphere-kudo":3143,
	"eng-mesosphere-ci":22467,
	"659706888171":0,
	"eng-mesosphere-terraform":526,
	"general-sales-se":5290
	}


class Dataset:
	var ds_id = ""
	var ds_name = ""
	var ds_is_zero := false
	var ds_value_temp = 0.0
	var ds_displaysize := Vector2.ZERO
	var ds_displaysize_temp := Vector2.ZERO
	var ds_displaypos := Vector2.ZERO
	var ds_value = 0.0
	var ds_scaled_value = 0.0
	var ds_color := Color.white
	var ds_box : Object = null


func _on_Button_pressed():
	$Button.hide()
	get_treemap_from_api(_g.main_graph.graph_data.id)


var api_response_data : Array
var api_error := false

func _ready():
	rect_size = treemap_size
	#create_treemap( fake_data )


func get_treemap_from_api( _graph_id:String ):
	api_response_data.clear()
	api_error = false
	
	_g.api.connect("api_response", self, "api_response")
	_g.api.connect("api_response_finished", self, "api_response_finished")
	
	var url : String = "/graph/" + _g.main_graph.graph_data.id + "/query/graph"
	var query = "is(account)"
	_e.emit_signal("api_request", HTTPClient.METHOD_POST, url, query)


func api_response( chunk:String ):
	if chunk == "" or chunk == "[" or chunk == "\n]" or chunk == ",\n" or chunk.begins_with("Error:"):
		if chunk.begins_with("Error:"):
			api_error = true
		return
	
	var parse_result : JSONParseResult = JSON.parse( chunk )
	if parse_result.error == OK:
		api_response_data.append( parse_result.result )


func api_response_finished():
	_g.api.disconnect("api_response", self, "api_response")
	_g.api.disconnect("api_response_finished", self, "api_response_finished")
	
	var account_dict:= {}
	for result in api_response_data:
		if "descendant_count" in result.metadata:
			account_dict[result.reported.name] = result.metadata.descendant_count
		
	create_treemap( account_dict )
	
	if api_error:
		print("API reported Error!")
		return
	print("API response finished!")


func clear_treemap():
	for d in datasets:
		d.ds_box.queue_free()
	datasets.clear()
	start = 0
	end = 0
	treemap_size_temp = treemap_size
	offset = Vector2.ZERO


func create_treemap( _data:Dictionary ):
	create_dataset_from_dict(_data)
	calc_map()
	fix_map()
	add_visuals()


func fix_map():
	for box in datasets:
		var pos_diff = box.ds_displaypos - box.ds_displaypos.round()
		box.ds_displaypos = box.ds_displaypos.round()
		box.ds_displaysize += pos_diff
		box.ds_displaysize = box.ds_displaysize.round()
		var edge_pos = box.ds_displaypos + box.ds_displaysize
		if edge_pos.x >= treemap_size.x-2:
			box.ds_displaysize.x = treemap_size.x - box.ds_displaypos.x
		if edge_pos.y >= treemap_size.y-2:
			box.ds_displaysize.y = treemap_size.y - box.ds_displaypos.y


func create_dataset_from_dict( _data:Dictionary ):
	var _data_keys = _data.keys()
	for i in _data.size():
		var _key = _data_keys[i]
		var new_dataset = Dataset.new()
		new_dataset.ds_id = str(i)
		new_dataset.ds_name = _key
		if _data[_key] <= 0:
			new_dataset.ds_is_zero = true
		new_dataset.ds_value = _data[_key]
		new_dataset.ds_value_temp = _data[_key]
		datasets.append(new_dataset)
	datasets.sort_custom(self, "sort_desc")


func add_visuals():
	var time_delay = 0.0
	for d in datasets:
		var new_element = TREEMAP_ELEMENT.instance()
		new_element.rect_position = d.ds_displaypos
		new_element.rect_size = Vector2.ZERO
		new_element.final_size = d.ds_displaysize
		new_element.element_color = d.ds_color
		new_element.label = d.ds_name
		new_element.value = d.ds_value if !d.ds_is_zero else 0
		new_element.show()
		d.ds_box = new_element
		add_child(new_element)
		
		time_delay += 0.01
		new_element.modulate.a = 0
		$Tween.interpolate_property(new_element, "rect_size", Vector2.ZERO, new_element.final_size, 0.2, Tween.TRANS_EXPO, Tween.EASE_OUT, time_delay)
		$Tween.interpolate_property(new_element, "modulate", Color.transparent, Color(2,2,2,1), 0.2, Tween.TRANS_EXPO, Tween.EASE_OUT, time_delay)
		$Tween.interpolate_property(new_element, "modulate", Color(2,2,2,1), Color.white, 1.0, Tween.TRANS_EXPO, Tween.EASE_OUT, time_delay+0.2)
	$Tween.start()


func calc_map():
	var value_scale := 0.0
	var value_total := 0.0
	
	var values_in_dataset := []
	for d in datasets:
		if d.ds_value_temp == 0:
			continue
		value_total += d.ds_value_temp
		values_in_dataset.append(d.ds_value_temp)
	
	if values_in_dataset.empty():
		return
	var smallest_value = float( values_in_dataset.min() )
	var biggest_value = float( values_in_dataset.max() )
	
	var zero_value = max(smallest_value/4, 1)
	for d in datasets:
		if d.ds_is_zero:
			d.ds_value_temp = zero_value
			d.ds_value = zero_value
			value_total += zero_value
	value_scale = ((treemap_size.x * treemap_size.y) / value_total) / 10
	
	for d in datasets:
		d.ds_value_temp *= value_scale
		d.ds_scaled_value = range_lerp(d.ds_value, smallest_value, biggest_value, 0, 1)
		d.ds_color = gradient.interpolate( d.ds_scaled_value )
	
	find_best_aspect()
	
	datasets[-1].ds_displaypos = offset


func find_best_aspect():
	while end < datasets.size():
		aspect_last = try(start, end, is_vert)
		if aspect_last > aspect_current or aspect_last < 1:
			var size_current := Vector2.ZERO
			
			for i in range(start, end+1):
				datasets[i].ds_displaypos = size_current + offset
				size_current += Vector2(0, datasets[i].ds_displaysize.y) if is_vert else Vector2(datasets[i].ds_displaysize.x, 0)
				
			offset += Vector2(datasets[start].ds_displaysize.x, 0) if is_vert else Vector2(0, datasets[start].ds_displaysize.y)
			
			treemap_size_temp = treemap_size - offset
			is_vert = aspect_vertical(treemap_size_temp)
			start = end
			end = start
			aspect_current = 9999999999999
			find_best_aspect()
		else:
			for i in range(start, end + 1):
				#if datasets[i].ds_is_zero:
				#	fit_zero_value_boxes(i)
				#	end = datasets.size()
				#	break
				datasets[i].ds_displaysize = datasets[i].ds_displaysize_temp
			aspect_current = aspect_last
		
		end += 1


func try(_start:int, _end:int, vertical:bool) -> float:
	var total := 0.0
	var aspect := 0.0
	var local_size := Vector2.ZERO
	
	for i in range(_start, _end + 1):
		total += datasets[i].ds_value_temp
	
	local_size = Vector2(total / treemap_size_temp.y * 10, treemap_size_temp.y) if vertical else Vector2(treemap_size_temp.x, total / treemap_size_temp.x * 10)#.round()
	
	for i in range(_start, _end + 1):
		if i > datasets.size():
			break
		
		if vertical:
			datasets[i].ds_displaysize_temp = Vector2(local_size.x, local_size.y * (datasets[i].ds_value_temp / total))#.round()
		else:
			datasets[i].ds_displaysize_temp = Vector2(local_size.x * (datasets[i].ds_value_temp / total), local_size.y)#.round()
		
		datasets[i].ds_displaysize_temp.x = max(datasets[i].ds_displaysize_temp.x, 1)
		datasets[i].ds_displaysize_temp.y = max(datasets[i].ds_displaysize_temp.y, 1)
		
		aspect = max( datasets[i].ds_displaysize_temp.y / datasets[i].ds_displaysize_temp.x, datasets[i].ds_displaysize_temp.x / datasets[i].ds_displaysize_temp.y )
		
	return aspect


func aspect_vertical( size:Vector2 ) -> bool:
	return size.x > size.y


func sort_desc(a, b) -> bool:
	if a.ds_value > b.ds_value:
		return true
	else:
		return false

