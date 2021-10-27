extends Node

# Start docker with:
# docker run -p 8900:8900 -e PSK="" ghcr.io/someengineering/cloudkeeper:latest --host 0.0.0.0

signal api_connected
signal api_response
signal api_response_finished

var http = HTTPClient.new()
var err = 0
var debug := true
var psk := "changeme"

onready var jwtlib = $JWT


func _ready():
	_g.api = self
	_e.connect("api_connect", self, "connect_to_core")
	_e.connect("api_request", self, "send_request")


func connect_to_core( adress := "http://127.0.0.1", port := 8900, timeout := 10 ):
	var had_timeout = false
	err = http.connect_to_host(adress, port)
	if err != OK:
		debug_message( "Error in connection! Check adress and port!" )
		return
	
	var timeout_start = OS.get_ticks_usec()
	while http.get_status() == HTTPClient.STATUS_CONNECTING or http.get_status() == HTTPClient.STATUS_RESOLVING:
		http.poll()
		var timout_measure = OS.get_ticks_usec()
		var timeout_time = (timout_measure - timeout_start)/1000000.0
		debug_message("Connecting... - Timer: " + str(timeout_time) + "sec")
		if timeout_time > timeout:
			had_timeout = true
			break
		
		if !OS.has_feature("web"):
			OS.delay_msec(500)
		else:
			yield(Engine.get_main_loop(), "idle_frame")
	
	if http.get_status() == HTTPClient.STATUS_CONNECTED:
		debug_message("Connected!")
		emit_signal("api_connected", had_timeout)


func send_request( method := HTTPClient.METHOD_GET, url := "/graph", query := "" ):
	if jwtlib.token == "" or !jwtlib.jwt_check_timeout():
		_e.emit_signal("create_jwt", "bla", psk)
		#yield(jwtlib, "jwt_generated")
	
	print(jwtlib.token)
	
	if http.get_status() != HTTPClient.STATUS_CONNECTED:
		debug_message("Problem with connection!")
		return
	
	var headers = [
		"User-Agent: Cloudkeeper UI",
		"Accept: */*",
		"Authorization: Bearer " + jwtlib.token
	]
	
	err = http.request(method, url, headers, query)
	
	if err != OK:
		debug_message( "Request error! Something went wrong when sending the request." )
		return

	while http.get_status() == HTTPClient.STATUS_REQUESTING:
		# Keep polling for as long as the request is being processed.
		http.poll()
		debug_message("Requesting...")
		if !OS.has_feature("web"):
			OS.delay_msec(500)
		else:
			# Synchronous HTTP requests are not supported on the web, wait for the next main loop iteration.
			yield(Engine.get_main_loop(), "idle_frame")
	
	# Make sure request finished well.
	if!(http.get_status() == HTTPClient.STATUS_BODY or http.get_status() == HTTPClient.STATUS_CONNECTED): 
		debug_message( "Request error! Something went wrong after the request." )
	
	var has_response = "ckcore has a response." if http.has_response() else "ckcore has no response."
	debug_message(has_response + "\n###########")

	if http.has_response():
		headers = http.get_response_headers_as_dictionary()
		debug_message("Response code: " + str(http.get_response_code()) )
		debug_message("Response headers:\n" + str(headers) )

		# Getting the response body
		if http.is_response_chunked():
			# Does it use chunks?
			debug_message("Response is Chunked!")
		else:
			# Or just plain Content-Length
			var body_length = http.get_response_body_length()
			debug_message("Response Length: "+ str(body_length) )

		var read_buffer = PoolByteArray()
		
		# While there is body left to be read, get chunks
		while http.get_status() == HTTPClient.STATUS_BODY:
			http.poll()
			var chunk = http.read_response_body_chunk()
			
			# Handling the response while receiving it from ckcore
			emit_signal("api_response", chunk.get_string_from_ascii() )
			
			# Eventually it would be time saving to use a different approach for
			# bigger requests, eg. only yielding every x results.
			# Yielding here allows the UI to react to the received response
			yield(get_tree(), "idle_frame")
			
			if chunk.size() == 0:
				if !OS.has_feature("web"):
					# Got nothing, wait for buffers to fill a bit.
					OS.delay_usec(1000)
				else:
					yield(Engine.get_main_loop(), "idle_frame")
			else:
				read_buffer += chunk # Append to read buffer.
				
		emit_signal( "api_response_finished" )
		debug_message("###########\nRequest finished!\nBytes received: " + str(read_buffer.size()) )
		
		# The following part is not neccessary at the moment as 
		# the result will be handled while receiving the response.
#		var request_result = read_buffer.get_string_from_ascii()
#		print("Result: ", result)

func debug_message( message:String ):
	if debug:
		print(message)
