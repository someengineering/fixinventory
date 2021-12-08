extends Popup

signal create_graph
signal use_example_data

const TEXT_ERROR_CONNECTION = "Can't connect to Cloudkeeper Core!\nPlease check if adress is correct, ports are open and ckcore is running."
const CONNECT_TEXT = "Connecting to Cloudkeeper Core. ({0}s)\n{1}:{2}"

var graph_id := "example"
var api_response_data: Dictionary

var adress: String
var port: int
var psk: String

onready var connect_input = find_node("ConnectInput")
onready var connect_btn = find_node("ConnectButton")
onready var retry_btn = find_node("RetryButton")
onready var psk_input = find_node("PSK")
onready var ok_btn = find_node("OkButton")
onready var graph_dropdown = find_node("GraphDropdown")
onready var graph_mode = find_node("GraphMode")
onready var status = find_node("ConnectMessage")
onready var box = find_node("CheckBox")


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
	_g.api.connect("api_connecting_timer", self, "api_connecting_timer")
	_g.api.connect("api_response", self, "api_response")
	_g.api.connect("api_response_finished", self, "api_response_finished")
	load_default_values()


func load_default_values():
	var connection_data = Utils.load_json("res://data/connection_data.json")
	if connection_data.empty():
		return
	$Margin/MarginContainer/Content/VBoxContainer/ConnectInput/Adress/AdressEdit.text = connection_data.server
	$Margin/MarginContainer/Content/VBoxContainer/ConnectInput/Port/PortEdit.text = str(connection_data.port)
	$Margin/MarginContainer/Content/VBoxContainer/PSK/PSKEdit.text = connection_data.psk


func popup_close():
	_g.popup = false
	hide()
	_g.api.disconnect("api_connected", self, "connected_to_core_msg")
	_g.api.disconnect("api_response", self, "api_response")
	_g.api.disconnect("api_response_finished", self, "api_response_finished")


func popup_ok():
	popup_close()
	graph_id = graph_dropdown.get_item_text(graph_dropdown.selected)

	var query: String
	match graph_mode.selected:
		0:
			query = "id(root) -[0:3]-> is(graph_root) or is(cloud) or is(account) or is(region)"
		1:
			query = "id(root) -[0:2]-> is(graph_root) or is(cloud) or is(account)"
		2:
			query = "is(graph_root) -[0:]->"

	_g.main_graph.graph_mode = graph_mode.selected
	_g.msg("query " + query)
	emit_signal("create_graph", graph_id, query)


func _on_ExampleDataButton_pressed():
	_g.use_example_data = true
	emit_signal("use_example_data", [])
	popup_close()


func _on_ConnectButton_pressed():
	# This is used to test connection to ck core
	adress = $Margin/MarginContainer/Content/VBoxContainer/ConnectInput/Adress/AdressEdit.text
	port = int($Margin/MarginContainer/Content/VBoxContainer/ConnectInput/Port/PortEdit.text)
	psk = $Margin/MarginContainer/Content/VBoxContainer/PSK/PSKEdit.text
	api_response_data.clear()
	connect_form_visible(false)
	status.text = CONNECT_TEXT.format(["0", adress, port])
	yield(VisualServer, "frame_post_draw")
	_e.emit_signal("api_connect", adress, port, psk, 10)


func connected_to_core_msg(had_timeout: bool):
	status.text = "Connected!\nGetting graphs..." if !had_timeout else TEXT_ERROR_CONNECTION
	yield(VisualServer, "frame_post_draw")
	if !had_timeout:
		_e.emit_signal("api_request")
	else:
		retry_btn.show()


func _on_RetryButton_pressed():
	retry_btn.hide()
	connect_form_visible(true)


func connect_form_visible(value: bool):
	connect_btn.visible = value
	connect_input.visible = value
	psk_input.visible = value
	status.visible = !value


func api_connecting_timer(time: float):
	status.text = CONNECT_TEXT.format([str(floor(time)), adress, port])


func api_response(chunk: String):
	api_response_data[api_response_data.size()] = parse_json(chunk)


func api_response_finished():
	if api_response_data[0] == null:
		status.text = "No Graphs found!"
		return
	graph_dropdown.show()
	graph_mode.show()
	status.text = "Select Graph"
	for i in api_response_data.values():
		graph_dropdown.add_item(i[0])
	ok_btn.show()


func _on_FileModeButton_pressed():
	popup_close()
	_e.emit_signal("load_nodes")
