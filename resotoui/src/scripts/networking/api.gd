extends Node

# Start docker with:
# docker run -p 8900:8900 ghcr.io/someengineering/resoto:latest --host 0.0.0.0
#
# Or start docker without JWT auth
# ( NOT recommended and NOT necessary anymore ):
# docker run -p 8900:8900 -e PSK="" ghcr.io/someengineering/resoto:latest --host 0.0.0.0

const DEFAULT_PSK = "changeme"
const DEBUG_MESSAGES := true

signal api_connected
signal api_connecting_timer
signal api_response
signal api_response_finished
signal api_response_total_elements

var connected := false
var http = HTTPClient.new()
var err = 0
var psk := DEFAULT_PSK
var current_adress := "http://127.0.0.1"
var current_port := 8900

onready var jwtlib = $JWT


func _ready():
	_g.api = self
	_e.connect("api_connect", self, "connect_to_core")
	_e.connect("api_request", self, "send_request")


func connect_to_core( adress := current_adress, port := current_port, _psk := psk, timeout := 5 ):
	var had_timeout = false
	current_adress = adress
	current_port = port

	err = http.connect_to_host(current_adress, current_port)
	if err != OK:
		debug_message("Error in connection! Check adress and port!")
		return

	var timeout_start = OS.get_ticks_usec()
	while (
		http.get_status() == HTTPClient.STATUS_CONNECTING
		or http.get_status() == HTTPClient.STATUS_RESOLVING
	):
		http.poll()
		var timout_measure = OS.get_ticks_usec()
		var timeout_time = (timout_measure - timeout_start) / 1000000.0
		debug_message("Connecting... - Timer: " + str(timeout_time) + "sec")
		emit_signal("api_connecting_timer", timeout_time)
		yield(get_tree(), "idle_frame")
		yield(get_tree(), "idle_frame")
		yield(get_tree(), "idle_frame")

		if timeout_time > timeout:
			had_timeout = true
			break

		if !OS.has_feature("web"):
			OS.delay_msec(100)
			#yield(Engine.get_main_loop(), "idle_frame")
		else:
			yield(get_tree(), "idle_frame")
			yield(get_tree(), "idle_frame")
			yield(get_tree(), "idle_frame")


	if http.get_status() == HTTPClient.STATUS_CONNECTED:
		debug_message("Connected!")
		connected = true
	else:
		debug_message("Could not connect - Timeout.")
		connected = false

	emit_signal("api_connected", had_timeout)
	psk = _psk if _psk != "" else DEFAULT_PSK


func check_status_and_reconnect():
	if http.get_status() != HTTPClient.STATUS_CONNECTED:
		connected = false
		debug_message("Problem with connection, trying to reconnect...")
		if http.get_status() == HTTPClient.STATUS_DISCONNECTED:
			connect_to_core()
			yield(self, "api_connected")
	return connected


func send_request( method := HTTPClient.METHOD_GET, url := "/graph", body := "" ):
	if jwtlib.token == "" or !jwtlib.token_expired():
		_e.emit_signal("create_jwt", "", psk)


	if http.get_status() != HTTPClient.STATUS_CONNECTED:
		connected = false
		debug_message("Problem with connection, trying to reconnect...")
		if http.get_status() == HTTPClient.STATUS_DISCONNECTED:
			connect_to_core()
			yield(self, "api_connected")

	if !connected:
		debug_message("Problem with connection, cancelling.")
		return

	var resotoui_via = "Web" if OS.has_feature("web") else "Desktop"

	var headers = [
		"User-Agent: resoto UI",
		"Accept: application/x-ndjson",
		"Resotoui-via: " + resotoui_via,
		"Authorization: Bearer " + jwtlib.token,
		"Content-Type: text/plain",
#		"Accept-Encoding: gzip"
	]

	if http.get_status() != HTTPClient.STATUS_CONNECTED:
		return

	err = http.request(method, url, headers, body)

	if err != OK:
		debug_message("Request error! Something went wrong when sending the request.")
		return

	while http.get_status() == HTTPClient.STATUS_REQUESTING:
		# Keep polling for as long as the request is being processed.
		http.poll()
		debug_message("Requesting...")
		if !OS.has_feature("web"):
			#yield(Engine.get_main_loop(), "idle_frame")
			OS.delay_msec(100)
		else:
			# Synchronous HTTP requests are not supported on the web, wait for the next main loop iteration.
			yield(get_tree(), "idle_frame")
			yield(get_tree(), "idle_frame")
			yield(get_tree(), "idle_frame")

	# Make sure request finished well.
	if !(
		http.get_status() == HTTPClient.STATUS_BODY
		or http.get_status() == HTTPClient.STATUS_CONNECTED
	):
		debug_message("Request error! Something went wrong after the request.")

	var has_response = (
		"resotocore has a response."
		if http.has_response()
		else "resotocore has no response."
	)
	debug_message(has_response + "\n###########")

	if http.has_response():
		headers = http.get_response_headers_as_dictionary()
		debug_message("Response code: " + str(http.get_response_code()))
		debug_message("Response headers:")
		var header_keys = headers.keys()
		for header_key in header_keys:
			debug_message(header_key + ": " + headers[header_key])

		if "Ck-Element-Count" in headers:
			emit_signal("api_response_total_elements", int( headers["Ck-Element-Count"] ) )

		var _gzip = "Content-Encoding" in headers and headers["Content-Encoding"] == "gzip"
		var _deflate = "Content-Encoding" in headers and headers["Content-Encoding"] == "deflate"

		# Getting the response body
		if http.is_response_chunked():
			# Does it use chunks?
			debug_message("Response is chunked.")
		else:
			debug_message("Response is non-chunked.")
			# Or just plain Content-Length
#			var body_length = http.get_response_body_length()
#			debug_message("Response Length: "+ str(body_length) )

		var read_buffer = PoolByteArray()

		var index := 0
		# While there is body left to be read, get chunks
		while http.get_status() == HTTPClient.STATUS_BODY:
			http.poll()
			var chunk = http.read_response_body_chunk()
			if chunk.size() == 0:
				if !OS.has_feature("web"):
					# Got nothing, wait for buffers to fill a bit.
					#yield(Engine.get_main_loop(), "idle_frame")
					OS.delay_usec(100)
				else:
					yield(get_tree(), "idle_frame")
					yield(get_tree(), "idle_frame")
					yield(get_tree(), "idle_frame")
			else:
				emit_signal("api_response", chunk.get_string_from_ascii())
				read_buffer += chunk # Append to read buffer.

			index += 1
			if index % 100 == 0:
				# Eventually it would be time saving to use a different approach for
				# bigger requests, eg. only yielding every x results.
				# Yielding here allows the UI to react to the received response
				yield(get_tree(), "idle_frame")


		yield(get_tree(), "idle_frame")
		emit_signal( "api_response_finished" )
		debug_message("###########\nRequest finished - Bytes received: " + str( read_buffer.size() ) )

		# The following part is not neccessary at the moment as
		# the result will be handled while receiving the response.


#		var request_result = read_buffer.get_string_from_ascii()
#		print("Result: ", result)


func debug_message( message:String ):
	if DEBUG_MESSAGES:
		print(message)
