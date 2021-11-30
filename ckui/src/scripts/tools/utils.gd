extends Node
class_name Utils


static func to_date(datetime:Dictionary) -> String:
	var date_string = "{0}.{1}.{2}".format([datetime.month, datetime.day, datetime.year], "{_}")
	return date_string


static func to_date_unix(unix_time:int) -> String:
	var datetime = OS.get_datetime_from_unix_time(unix_time)
	var date_string = "{0}.{1}.{2}".format([datetime.month, datetime.day, datetime.year], "{_}")
	return date_string


static func load_json(path) -> Dictionary:
	var file = File.new()
	if !file.file_exists(path):
		return {}
	file.open(path, file.READ)
	var tmp_text = file.get_as_text()
	file.close()
	var data = parse_json(tmp_text)
	return data


static func save_json(path, data):
	var file = File.new()
	file.open(path, file.WRITE)
	file.store_string( to_json(data) )
	file.close()


static func get_random_pos_3D(_radius:=500.0, _z_depth:=20.0) -> Vector3:
	var random_vec2 = Vector2(rand_range(_radius*0.75, _radius), 0).rotated(randf()*TAU)
	return Vector3(random_vec2.x, random_vec2.y, rand_range(-_z_depth, _z_depth))
