extends MeshInstance

var default_material_color = Color("#412d76aa")


func highlight( _active:= false ):
	if _active:
		material_override.albedo_color = default_material_color * 3
	else:
		material_override.albedo_color = default_material_color
