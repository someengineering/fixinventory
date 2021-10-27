extends Popup

signal create_graph
signal use_example_data

const TEXT_ERROR_CONNECTION = "Can't connect to Cloudkeeper Core!\nPlease check if ports are open and ckcore is running."

var graph_id := "example"
var api_response_data : Dictionary

onready var output = $Margin/MarginContainer/Content/VBoxContainer/Output
onready var ok_btn = $Margin/MarginContainer/PopupButtons/OkButton
onready var status = $Margin/MarginContainer/Content/VBoxContainer/ConnectMessage
onready var box = $Margin/MarginContainer/Content/VBoxContainer/CheckBox
onready var dropdown = $Margin/MarginContainer/Content/VBoxContainer/GraphSelect/GraphDropdown


func _ready():
	_e.connect("connect_popup", self, "popup_show")

func _on_CancelButton_pressed():
	popup_close()


func _on_OkButton_pressed():
	popup_ok()


func popup_show():
	_g.popup = true
	show()
	_g.api.connect("api_connected", self, "connected_to_core_msg")
	_g.api.connect("api_response", self, "api_response")
	_g.api.connect("api_response_finished", self, "api_response_finished")


func popup_close():
	_g.popup = false
	hide()
	_g.api.disconnect("api_connected", self, "connected_to_core_msg")
	_g.api.disconnect("api_response", self, "api_response")
	_g.api.disconnect("api_response_finished", self, "api_response_finished")


func popup_ok():
	popup_close()
	graph_id = dropdown.get_item_text(dropdown.selected)
	var query : String = "is(graph_root) -[0:]->"
	emit_signal("create_graph", graph_id, query)


func _on_ExampleDataButton_pressed():
	_g.use_example_data = true
	emit_signal( "use_example_data", [] )
	popup_close()


func _on_ConnectButton_pressed():
	# This is used to test connection to ck core
	var adress = $Margin/MarginContainer/Content/VBoxContainer/ConnectInput/Adress/AdressEdit.text
	var port = int($Margin/MarginContainer/Content/VBoxContainer/ConnectInput/Port/PortEdit.text)
	api_response_data.clear()
	
	var connect_text = "Connecting to Cloudkeeper Core...\n{0}:{1}"
	$Margin/MarginContainer/Content/VBoxContainer/ConnectInput.hide()
	status.show()
	status.text = connect_text.format([adress, port])
	yield(VisualServer, "frame_post_draw")
	_e.emit_signal( "api_connect", adress, port, 10 )
	
	
func connected_to_core_msg(had_timeout:bool):
	status.text = "Connected!\nRequesting graphs..." if !had_timeout else TEXT_ERROR_CONNECTION
	yield(VisualServer, "frame_post_draw")
	_e.emit_signal("api_request")


func api_response( chunk:String ):
	api_response_data[ api_response_data.size() ] = parse_json(chunk)
	

func api_response_finished():
	if api_response_data[0] == null:
		status.text = "No Graphs found!"
		return
	$Margin/MarginContainer/Content/VBoxContainer/GraphSelect.show()
	status.text = "Select Graph"
	for i in api_response_data.values():
		dropdown.add_item(i[0])
	$Margin/MarginContainer/PopupButtons/OkButton.show()


func _on_FileModeButton_pressed():
	popup_close()
	_e.emit_signal("load_nodes")
