--[[
Copyright © 2015 Dynatrace LLC. 
All rights reserved. 
Unpublished rights reserved under the Copyright Laws of the United States.

U.S. GOVERNMENT RIGHTS-Use, duplication, or disclosure by the U.S. Government is
subject to restrictions as set forth in Dynatrace LLC license agreement and as
provided in DFARS 227.7202-1(a) and 227.7202-3(a) (1995), DFARS
252.227-7013(c)(1)(ii) (OCT 1988), FAR 12.212 (a) (1995), FAR 52.227-19, 
or FAR 52.227-14 (ALT III), as applicable.

This product contains confidential information and trade secrets of Dynatrace LLC. 
Disclosure is prohibited without the prior express written permission of Dynatrace LLC. 
Use of this product is subject to the terms and conditions of the user's License Agreement with Dynatrace LLC.
See the license agreement text online at https://community.dynatrace.com/community/download/attachments/5144912/dynaTraceBSD.txt?version=3&modificationDate=1441261477160&api=v2
--]]


--[[

Java Sun RMI parsing script

]]--

local CALLDATA = 0x50
local RETURNDATA = 0x51
local STREAM_MAGIC = 0xaced
local STREAM_VERSION = 0x0005

local TC_NULL = 0x70
local TC_REFERENCE = 0x71
local TC_CLASSDESC = 0x72
local TC_OBJECT = 0x73
local TC_STRING = 0x74
local TC_ARRAY = 0x75
local TC_CLASS = 0x76
local TC_BLOCKDATA = 0x77
local TC_ENDBLOCKDATA = 0x78
local TC_RESET = 0x79
local TC_EXCEPTION = 0x7B
local TC_PROXYCLASSDESC = 0x7D
local TC_ENUM = 0x7E

local SC_WRITE_METHOD = 0x01
local SC_BLOCK_DATA = 0x08
local SC_SERIALIZABLE = 0x02
local SC_EXTERNALIZABLE = 0x04
local SC_ENUM = 0x10

local BASE_WRITE_HANDLE = 0x7E0000

local CALLTYPE_OFFSET = 1
local STREAM_MAGIC_NUMBER_OFFSET = 2
local STREAM_VERSION_OFFSET = 4
local HEADER_END_OFFSET = 6
local OPERATION_NUMBER_OFFSET = 8
local NUMBER_OFFSET = OPERATION_NUMBER_OFFSET + 8
local TIMESTAMP_OFFSET = NUMBER_OFFSET + 4
local COUNT_OFFSET = TIMESTAMP_OFFSET + 8
local OPERATION_OFFSET = COUNT_OFFSET + 2
local OPERATION_HASH_OFFSET = OPERATION_OFFSET + 4

local RETURN_VALUE_OK = 0x01
local RETURN_VALUE_EXCEPTION = 0x2
local RETURN_CODE_OFFSET = 8

local function unpack_short(pstr, offset)
	--  struct.unpack(">I2", pstr:sub(offset, offset + 2))
	return (pstr:byte(offset) * 256) + (pstr:byte(offset + 1))
end


local function unpack_number(pstr, offset, size)
	local number = 0
	local max = size - 1
	for i = 0, max do
		number = number * 256
		number = (number + pstr:byte(offset + i))
	end 
	return number
end

--[ debug function ]--
local function print_hex(pstr, offset, len)
	for idx, el in ipairs({pstr:byte(offset, offset + len)}) do
		print(idx, string.format('0x%0x', el))
	end
end

--[ debug function to print string as a hex string ]--
local function HexDumpString(str)
	return (
		string.gsub(str,"(.)",
			function (c)
				return string.format("%02X%s",string.byte(c), "")
			end
		)
	)
end

--[ read short string ]--
local function parse_string(payload, position)
	--print("Started parsing at position: ", position)
	local len = unpack_short(payload, position)
	position = position + 2
	local name = payload:sub(position, position + len -1 )
	--print_hex(name, 0, name:len()) 
	return name
end

--[ read next object corresponding to the spec grammar rule "content" and return an object of type content" ]---
local function read_content(payload, position)
	local pos = position
	local byte = payload:byte(pos)
	pos = pos + 1
	if byte == TC_OBJECT then
		print("New Object")
	elseif byte == TC_CLASS then
		print("New Class")
	elseif byte == TC_ARRAY then
		print("New Array")
	elseif byte == TC_STRING then
		print("New String")
	elseif byte == TC_ENUM then
		print("New Enum")
	elseif byte == TC_REFERENCE then
		print("New Reference")
	elseif byte == TC_NULL then
		return {0, pos - position}
	elseif byte == TC_EXCEPTION then
		print("New Exception")
	elseif byte == TC_BLOCKDATA then
		error("BlockData not allowed here!")
	else
		print("Unknown content TC byte in stream: ", string.format("%02x", byte))
	end
	return {0, pos - position}
end

--[ parse class annotation ]--
local function read_classAnnotation(payload, position)
	local list = {}
	local finish = false
	local pos = position
	repeat
		local byte = payload:byte(pos)
		--print("Byte: ", string.format("%x", byte))
		
		if byte == TC_ENDBLOCKDATA then
			finish = true
			pos = pos + 1
			--print("Finish")
		elseif byte == TC_RESET then
			list = {} -- create new list
			pos = pos + 1
			--print("Reset")
		else
			--print("Other")
			local val = read_content(payload, pos)
			pos = pos + val[2]
		end
	until finish == true
	
	return {list, pos - position}
end

local function parse_object(payload, position)
	local pos = position
	if payload:byte(pos) ~= TC_OBJECT then
		return 0
	end
	pos = pos + 1
	
	if payload:byte(pos) ~= TC_CLASSDESC then
		return 0
	end
	pos = pos + 1 
	
	local className = parse_string(payload, pos)
	pos = pos + className:len() + 2 -- + 2 due to str len

	local serialVersionUID = payload:sub(pos, pos + 8) --long
	pos = pos + 8
	
	local classDescFlags = payload:byte(pos)
	pos = pos + 1
	--print("classDescFlags: ", string.format("%x", classDescFlags))
	
	local fields =  unpack_short(payload, pos)
	pos = pos + 2
	if fields < 0 then
		error("Invalid field count: ", fields)
	end
	--print("Fields: ", fields)
	
	local ret = read_classAnnotation(payload, pos)
	local list = ret[1]
	--print("Test: ", ret[2])
	pos = pos + ret[2]
	--print("Byte: ", string.format("%x", payload:byte(pos)))
	
	
	return className	
end

function script_name()
        return "Sun RMI script"
end

function parse_parameters(payload, stats)
        return 0
end


function parse_request(payload, stats)
	if payload:byte(CALLTYPE_OFFSET) ~= CALLDATA then
		error('Not a request message')
		return 1
	end
	
	if unpack_short(payload, STREAM_MAGIC_NUMBER_OFFSET) ~= STREAM_MAGIC then
		error('Invalid stream magic number')
		return 1
	end
	
	if unpack_short(payload, STREAM_VERSION_OFFSET) ~= STREAM_VERSION then
		error('Invalid stream version')
		return 1
	end
	
	if payload:byte(HEADER_END_OFFSET) == TC_BLOCKDATA then
		local blockDataLen = unpack_number(payload, HEADER_END_OFFSET + 1, 1) 
		if blockDataLen >= 0x22 then
			--local opNumber = payload:sub(OPERATION_NUMBER_OFFSET, NUMBER_OFFSET)
			--print ("opNumber: ") print_hex(opNumber, 0, 8)
			
			--local number = payload:sub(NUMBER_OFFSET, TIMESTAMP_OFFSET)
			--print ("number: ") print_hex(number, 0, 4)
			
			--local timestamp = payload:sub(TIMESTAMP_OFFSET, COUNT_OFFSET)
			--print ("timestamp: ") print_hex(timestamp, 0, 8)
			
			--local count =  payload:sub(COUNT_OFFSET, OPERATION_OFFSET)
			--print ("count: ") print_hex(count, 0, 2)
			
			--local operation = payload:sub(OPERATION_OFFSET, OPERATION_HASH_OFFSET)
			--print ("operation: ") print_hex(operation, 0, 4)
			
			local opHash = payload:sub(OPERATION_HASH_OFFSET, OPERATION_HASH_OFFSET + 7)
			--print ("Operation hash: ") print_hex(opHash, 0, 8)
			local result, text, len= stats:getDictText(opHash, opHash:len())
			--print ("Test result: " , result , " text: " , text, " len: ", len)
			if result == true then
				stats:setOperationName(text, len)
			else
				stats:setOperationName(opHash, opHash:len())
			end
		end
	end
	
	return 0
end

function parse_response(payload, stats)
	if payload:byte(CALLTYPE_OFFSET) ~= RETURNDATA then
		error('Not a response message')
		return 1
	end
	
		if unpack_short(payload, STREAM_MAGIC_NUMBER_OFFSET) ~= STREAM_MAGIC then
		error('Invalid stream magic number')
		return 1
	end
	
	if unpack_short(payload, STREAM_VERSION_OFFSET) ~= STREAM_VERSION then
		error('Invalid stream version')
		return 1
	end
	
	if payload:byte(HEADER_END_OFFSET) == TC_BLOCKDATA then
		local blockDataLen = unpack_number(payload, HEADER_END_OFFSET + 1, 1) 
		if blockDataLen == 0x0f then
			local returnCode = payload:byte(RETURN_CODE_OFFSET)
			if (returnCode == RETURN_VALUE_EXCEPTION) then
				local className = parse_object(payload, HEADER_END_OFFSET + blockDataLen + 2)
				stats:setAttribute(1, className)
			end
		end
	end
	
	return 0;
end


local the_module = {}
the_module.parse_parameters = parse_parameters
the_module.parse_request = parse_request
the_module.parse_response = parse_response
return the_module
