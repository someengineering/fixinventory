extends Node

signal jwt_generated


func _ready():
	_e.connect("create_jwt", self, "create_jwt")


func create_jwt(data:String, secret:String):
	emit_signal( "jwt_generated", jwt(data, secret) )


func jwt(data:String, secret:String):
	var expire = OS.get_unix_time() + 300
	var crypto = Crypto.new()

	var header = {
		"alg": "HS256",
		"typ": "JWT"
	}
	var payload = {
		"exp": expire,
		"data": data
	}

	var header_base64 = base64urlencode(Marshalls.utf8_to_base64(JSON.print(header)))
	var payload_base64 = base64urlencode(Marshalls.utf8_to_base64(JSON.print(payload)))
	
	var signing_content = header_base64 + "." + payload_base64
	
	var signature = crypto.hmac_digest(HashingContext.HASH_SHA256, secret.to_utf8(), signing_content.to_utf8())
	signature =  base64urlencode(Marshalls.raw_to_base64(signature))

	var jwt = signing_content + "." + signature
	return jwt


static func pbkdf2(hash_type: int, password: PoolByteArray, salt: PoolByteArray, iterations := 100000, length := 0) -> PoolByteArray:
	var crypto := Crypto.new()
	var hash_length := len(crypto.hmac_digest(hash_type, salt, password))
	if length == 0:
		length = hash_length
	
	var output := PoolByteArray()
	var block_count := ceil(length / hash_length)
	
	var buffer := PoolByteArray()
	buffer.resize(4)
	
	var block := 1
	while block <= block_count:
		buffer[0] = (block >> 24) & 0xFF
		buffer[1] = (block >> 16) & 0xFF
		buffer[2] = (block >> 8) & 0xFF
		buffer[3] = block & 0xFF
		
		var key_1 := crypto.hmac_digest(hash_type, password, salt + buffer)
		var key_2 := key_1
		
		for _index in iterations - 1:
			key_1 = crypto.hmac_digest(hash_type, password, key_1)
			
			for index in key_1.size():
				key_2[index] ^= key_1[index]
		
		output += key_2
		
		block += 1
	
	return output.subarray(0, hash_length - 1)


static func base64urlencode(base64_input):
	return str(base64_input).replace("+", "-").replace("/", "_").trim_suffix("==")

#static func key_from_psk( psk: String, salt: PoolByteArray = [] ) -> Dictionary:
#	if salt.empty():
#		salt = Crypto.new().generate_random_bytes(16)
#	var key = pbkdf2(HashingContext.HASH_SHA256, str(psk).to_utf8(), salt, 100000)
#	return {"key": key, "salt": salt}
