extends MeshInstance

var default_material_color = Color("#46ffffff")


func highlight( _active:= false ):
	if _active:
		material_override.albedo_color = default_material_color * 2
	else:
		material_override.albedo_color = default_material_color
