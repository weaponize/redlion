--
-- thoughtleader@internetofallthethings.com
--

cr3_proto = Proto("cr3","Crimson v3")

-- define the field names, widths, descriptions, and number base
-- looks like lua structs is what I should use here
local pf_payload_length = ProtoField.uint16("cr3.len", "Length", base.HEX)
local pf_reg = ProtoField.uint16("cr3.reg", "Register number", base.HEX)
local pf_payload = ProtoField.bytes("cr3.payload", "Payload")
local ptype = ProtoField.uint16("cr3.payload.type", "Type", base.HEX)
local pzero = ProtoField.uint16("cr3.payload.zero", "Zero", base.HEX)

local pdata = ProtoField.bytes("cr3.payload.data", "Data")
local pstring = ProtoField.string("cr3.payload.string", "String")

-- 0x1000 GUID
-- RedLion uses the mixed endian in CR3 files 
-- C49E83B0-F495-46E8-B96E-98A64BC2A0C9
local p_1000_uuid = ProtoField.guid("cr3.payload.guid", "GUID")

-- 0x1600 GUID
-- 
local p_1600_uuid = ProtoField.guid("cr3.payload.guid", "GUID")

-- 0x1300
local p_1300_seq = ProtoField.uint16("cr3.payload.sequence", "Sequence", base.HEX)
local p_1300_subtype = ProtoField.uint16("cr3.payload.subtype", "Subtype", base.HEX)
local p_1300_value = ProtoField.uint32("cr3.payload.value", "Value", base.HEX)
local p_1700_value = p_1300_value

-- 0x1400
local p_1400_seq = ProtoField.uint16("cr3.payload.sequence", "Sequence", base.HEX)
local p_1400_subtype = ProtoField.uint16("cr3.payload.subtype", "Subtype", base.HEX)
local p_1400_length = ProtoField.uint32("cr3.payload.length", "Length to be sent", base.HEX)

-- 0x1500
-- start 32bit
-- length
local p_1500_chunkstart = ProtoField.uint32("cr3.payload.chunkstart", "Chunk start", base.HEX)
local p_1500_chunklength = ProtoField.uint16("cr3.payload.chunklength", "Chunk Length", base.HEX)
local p_1500_chunkdata = ProtoField.bytes("cr3.payload.chunkdata", "Chunk Data")

-- 0x1900
-- Send time and date
local p_1900_seconds = ProtoField.uint8("cr3.payload.seconds", "Seconds", base.DECIMAL)
local p_1900_minutes = ProtoField.uint8("cr3.payload.minutes", "Minutes", base.DECIMAL)
local p_1900_hours = ProtoField.uint8("cr3.payload.hours", "Hours", base.DECIMAL)
local p_1900_day = ProtoField.uint8("cr3.payload.day", "Day", base.DECIMAL)
local p_1900_month = ProtoField.uint8("cr3.payload.month", "Month", base.DECIMAL)
local p_1900_year = ProtoField.uint8("cr3.payload.year", "Year", base.DECIMAL)

-- 0x1b00
-- 32bit zero
-- 16bit readoffset
-- 16bit readlength
local p_1b00_zero = ProtoField.uint16("cr3.payload.zero", "Zero", base.HEX)
local p_1b00_readoffset = ProtoField.uint32("cr3.payload.readoffset", "Read offset", base.HEX)
local p_1b00_readlength = ProtoField.uint16("cr3.payload.readlength", "Read length", base.HEX)

-- 0x0300
-- Responses seem to be subtyped based on the register number
local p_0300_22b_len1 = ProtoField.uint32("cr3.payload.dblength1", "DB length1", base.HEX)
local p_0300_22b_len2 = ProtoField.uint32("cr3.payload.dblength2", "DB length2", base.HEX)

-- example I followed said not to do the fields like this, risk of missing some
cr3_proto.fields = {
	pf_payload_length,
	pf_reg,
	pf_payload,
	ptype,
	pstring,
	pdata,
	p_0300_22b_len1,
	p_0300_22b_len2,
	p_1000_uuid,
	p_1300_seq,
	p_1300_subtype,
	p_1300_value,
	p_1400_seq,
	p_1400_subtype,
	p_1400_length,
	p_1500_chunkstart,
	p_1500_chunklength,
	p_1500_chunkdata,
	p_1600_uuid,
	p_1900_seconds,
	p_1900_minutes,
	p_1900_hours,
	p_1900_day,
	p_1900_month,
	p_1900_year,
	p_1b00_zero,
	p_1b00_readoffset,
	p_1b00_readlength
}

-- ProtoExpert
local payload_expert = ProtoExpert.new("cr3.payload_unexpected", "Unexpected or unknown protocol message", expert.group.MALFORMED, expert.severity.ERROR)
local other_expert   = ProtoExpert.new("cr3.other_unexpected", "Other error", expert.group.MALFORMED, expert.severity.ERROR)
cr3_proto.experts = { payload_expert, other_expert }

-- trying out a global variable for processing any cr3 segments
local processing_segment = false
-- local reassembled_length = 0
-- local segment_cur = 0 
-- local segment_data = nil

function cr3_proto.dissector(tvbuf,pinfo,tree)

	-- length of the received packet
	local pktlen = tvbuf:reported_length_remaining()
	local cr3len
	if not processing_segment then
		-- pf_payload_length
		cr3len = tvbuf(0,2):uint()

		if pktlen == cr3len + 2 then
			dissect_cr3(tvbuf, pinfo, tree, cr3len)
			return
		elseif cr3len > pktlen then
			processing_segment = true
			pinfo.desegment_len = cr3len - pktlen + 2
			return
		else
			-- checking if this ever hits
			print "SHOULD NOT HIT THIS"
			return
		end
	else
		-- preumption is that setting desegment_len
		-- means we won't get called until we recv that much
		cr3len = tvbuf(0,2):uint()
		dissect_cr3(tvbuf, pinfo, tree, cr3len)
		processing_segment = false
		return
	end
		
end

function dissect_cr3(tvbuf,pinfo,tree,cr3len)

	-- set the protocol column based on the Proto object
	pinfo.cols.protocol = cr3_proto.description
	
	-- length of the entire CR3 payload
	local pktlen = tvbuf:reported_length_remaining()
	
	-- define this entire length as the object of dissection
	local subtree = tree:add(cr3_proto, tvbuf:range(0, pktlen))
		
	-- setup fields in the proper order and width
	local offset = 0
		
	local cr3len = tvbuf(offset,2):uint()
	subtree:add(pf_payload_length,tvbuf(offset,2))
	offset = offset + 2
		
	local reg = tvbuf(offset,2):uint()
	subtree:add(pf_reg, reg)
	offset = offset + 2
	
	-- payload gets broken out
	local payloadtree = subtree:add(pf_payload, tvbuf:range(offset, pktlen - offset))
	payloadtree:set_text("Payload: ")
	
	local packettype = tvbuf:range(offset, 2):uint()
	local packettypetree = payloadtree:add(ptype, packettype)
	offset = offset + 2

	type_description = ""
	error = false

	-- the idea of using packettype might be wrong
	-- the register seems like it might be the main identifier
	-- and/or there's a relationship between reg/packettype

	-- type-specific handling here
	-- packettype 0x0100
	if packettype == 0x0100 then
		-- no data
		type_description = "ONE HUNDRED"

	elseif packettype == 0x0200 then
		-- no data
		type_description = "TWO HUNDRED"
		
	elseif packettype == 0x0300 then
	
		-- these registers are responses to make/model queries
		if (reg == 0x012a or reg == 0x012b) then
			string = tvbuf:range(offset):stringz()
			payloadtree:add(pstring, string)
			type_description = string.format("RESPONSE: %s", string)

		elseif reg==0x12f then
			local length = tvbuf:range(offset,4):uint()
			type_description = string.format("BOOT VERSION: %d", length)

		-- these registers are responses to request for database size prior to download
		elseif (reg == 0x022a or reg == 0x022b) then

			local length1=0
			local length2=0

			-- sometimes the device will only report 4 bytes
			if cr3len >= 0x08 then
				length1 = tvbuf(offset,4):uint()
				offset = offset + 4
				payloadtree:add(p_0300_22b_len1, length1)
			end

			-- often, the device will report two identical lengths
			if cr3len >= 0x0c then
				length2 = tvbuf(offset,4):uint()
				offset = offset + 4
				payloadtree:add(p_0300_22b_len2, length2)
			end 

			type_description = string.format("RESPONSE DB length1: 0x%0x, DB length2: 0x%0x", length1, length2)

		elseif cr3len == 0x05 then
			data = tvbuf:range(offset)
			payloadtree:add(pdata,data)
			type_description = string.format("RESPONSE: %s", tostring(data))
		else
			-- type_description = string.format("Unhandled 0x300 response")
			local data = tvbuf:range(offset)
			payloadtree:add(pdata, data)
			type_description = string.format("DATA TRANSFER: 0x%x bytes", data:len())
		end

	elseif packettype == 0x1000 then
		-- 16 byte read

		-- Manual mixed endian decode
		-- this is only for display
		-- for comparison to GUID RESET, use the method that already works
		-- NOTE: doing copy/value in wireshark does not get the mixed endian string, it gets the bigendian
		-- => likely because of the pauloadtree:add() call below
		local guid_1_32le = tvbuf:range(offset,4):le_uint()
		local guid_2_16le = tvbuf:range(offset+4,2):le_uint()
		local guid_3_16le = tvbuf:range(offset+6,2):le_uint()
		local guid_4_16be = tvbuf:range(offset+8,2):uint()
		local guid_5_32be = tvbuf:range(offset+10,4):uint()
		local guid_5_16be = tvbuf:range(offset+14,2):uint()
		local guid_mixed_endian = string.format("%08x-%04x-%04x-%04x-%08x%04x", guid_1_32le, guid_2_16le, guid_3_16le, guid_4_16be, guid_5_32be, guid_5_16be)

		-- still reading in the raw bytes and setting that
		-- might cause problems
		local guid = tvbuf:range(offset)
		local guiditem = payloadtree:add(p_1000_uuid, guid)
		guiditem:set_text(string.format("GUID: %s", guid_mixed_endian))

		-- this GUID tells the device a GUID check is about to be requested (?)
		-- lower hex digits matters
		-- should probably just convert this to the mixed endian string and compare to guid_mixed_endian
		local reset_guid = string.lower(tostring(ByteArray.new("9EB339B9DC8A494C820CDF7D2D44566D")))
		local packet_guid = tostring(guid)

		-- this GUID tells the device a GUID check is about to be requested (?)
		if reset_guid == packet_guid then
			type_description = string.format("GUID RESET", guid_mixed_endian)
		else 
			-- 
			-- if the GUID is not the hardcoded one above, 
			-- this is the GUID to check/set
			-- hardware will respond 0 if that doesn't match the current config
			-- hardware will respond 1 if that DOES MATCH the current config
			-- if doesn't match, crimson will update the device
			-- if DOES MATCH, crimson will CRC(?) check all the "files"/registers
			type_description = string.format("GUID: %s", guid_mixed_endian)
		end
				
	elseif packettype == 0x1600 then
		-- 16 byte read
		if cr3len == 0x14 then
			local guid = tvbuf:range(offset)
			local packet_guid = tostring(guid)

			-- display the mixed endian guid
			local guid_1_32le = tvbuf:range(offset,4):le_uint()
			local guid_2_16le = tvbuf:range(offset+4,2):le_uint()
			local guid_3_16le = tvbuf:range(offset+6,2):le_uint()
			local guid_4_16be = tvbuf:range(offset+8,2):uint()
			local guid_5_32be = tvbuf:range(offset+10,4):uint()
			local guid_5_16be = tvbuf:range(offset+14,2):uint()
			local guid_mixed_endian = string.format("%08x-%04x-%04x-%04x-%08x%04x", guid_1_32le, guid_2_16le, guid_3_16le, guid_4_16be, guid_5_32be, guid_5_16be)
	
			local guiditem = payloadtree:add(p_1600_uuid,guid)
			guiditem:set_text(string.format("GUID: %s", guid_mixed_endian))


			type_description = string.format("VERIFY GUID %s", guid_mixed_endian)
		else
			error = true
			type_description = string.format("subtype 0x1000, length violates assumption 0x%x", cr3len)
			payloadtree:add_proto_expert_info(payload_expert, type_description)
		end

	elseif packettype == 0x1100 then
		if cr3len > 4 then
			local data = tvbuf:range(offset)
			payloadtree:add(pdata, data)

			type_description = "0x1100 (data)"
		else
			type_description = "0x1100 (empty)"
		end

	elseif packettype == 0x1300 then
		-- sequence
		-- type 
		-- value
		if not (cr3len == 0x0c) then
			error = true
			type_description = string.format("subtype 0x%04x, length violates assumption", packettype)
		end

		local seq = tvbuf(offset,2):uint()
		offset = offset + 2
		local subtype = tvbuf(offset,2):uint()
		offset = offset + 2
		local value = tvbuf(offset,4):uint()
		offset = offset + 4

		payloadtree:add(p_1300_seq,seq)
		payloadtree:add(p_1300_subtype,subtype)
		payloadtree:add(p_1300_value,value)

		type_description = string.format("CRC 0x%04x, 0x%08x", seq, value)
		
		
	elseif packettype == 0x1400 then
		-- sequence
		-- type 
		-- value
		if cr3len == 0x0c then
			local seq = tvbuf(offset,2):uint()
			offset = offset + 2
			local subtype = tvbuf(offset,2):uint()
			offset = offset + 2
			local value = tvbuf(offset,4):uint()
			offset = offset + 4

			payloadtree:add(p_1400_seq,seq)
			payloadtree:add(p_1400_subtype,subtype)
			payloadtree:add(p_1400_length,value)

			-- packettypetree:append_text(string.format("WILL_SEND 0x%08x", value))
			type_description = string.format("WILL_SEND 0x%x", value)
		else
			-- 0x1400 with no data might be EOF or something
			type_description = "EOF"
		end

	elseif packettype == 0x1200 or packettype == 0x1202 or packettype == 0x1500 then

		if cr3len > 4 then
			-- start
			-- length

			local chunkstart = tvbuf(offset,4):uint()
			offset = offset + 4
			local chunklength = tvbuf(offset,2):uint()
			offset = offset + 2
			local chunkdata = tvbuf(offset)

			payloadtree:add(p_1500_chunkstart, chunkstart)
			payloadtree:add(p_1500_chunklength, chunklength)
			payloadtree:add(p_1500_chunkdata, chunkdata)

			type_description = string.format("DATA TRANSFER 0x%x", chunklength)
		else
			error = true
			type_description = string.format("subtype 0x%04x, length violates assumption", packettype)
		end

	elseif packettype == 0x1700 then
		-- seems to always read 0x7530 (30000)
		local value = tvbuf(offset,4):uint()
		payloadtree:add(p_1700_value, value)

		type_description = "0x1700"
		
	elseif packettype == 0x1800 then
		-- no read

		type_description = "SAVE COMMAND(?) 0x1800"
		
	elseif packettype == 0x1a00 then

		if reg == 0x22b then
			type_description = "DB_LEN QUERY"
		elseif cr3len == 4 then
			local data = tvbuf:range(offset)
			payloadtree:add(pdata, data)
			type_description = "MODEL"
		else
			type_description = "Unhandled 0x1a00 subtype"
		end

		

	elseif packettype == 0x1900 then		
		-- 
		local seconds = tvbuf:range(offset,1):uint()
		offset = offset + 1
		local minutes = tvbuf:range(offset,1):uint()
		offset = offset + 1
		local hours = tvbuf:range(offset,1):uint()
		offset = offset + 1
		local day = tvbuf:range(offset,1):uint()
		offset = offset + 1
		local month = tvbuf:range(offset,1):uint()
		offset = offset + 1
		local year = tvbuf:range(offset,1):uint()
		offset = offset + 1

		payloadtree:add(p_1900_seconds, seconds)
		payloadtree:add(p_1900_minutes, minutes)
		payloadtree:add(p_1900_hours, hours)
		payloadtree:add(p_1900_day, day)
		payloadtree:add(p_1900_month, month)
		payloadtree:add(p_1900_year, year)

		local datestring = string.format("DATE/TIME %02d-%02d-%02d %02d:%02s:%02d", year, month, day, hours, minutes, seconds)
		payloadtree:append_text(datestring)
		type_description = datestring

	elseif packettype == 0x1b00 then
		if cr3len >= 0x0c then
		
			local zero = tvbuf(offset,2):uint() 
			offset = offset + 2
			local readoffset = tvbuf(offset,4):uint() 
			offset = offset + 4
			local readlength = tvbuf(offset,2):uint() 
			offset = offset + 2
			
			payloadtree:add(p_1b00_zero, zero)
			payloadtree:add(p_1b00_readoffset, readoffset)
			payloadtree:add(p_1b00_readlength, readlength)
			type_description = string.format("READ_LENGTH 0x%x", readlength)
		else
			-- 
			type_description = "MAKER"
		end

		

		
	elseif packettype == 0x1c00 then
		-- no read
		
		type_description = "BOOT VERSION"

	elseif packettype == 0x1e00 then
		-- one byte
		local data = tvbuf:range(offset)
		payloadtree:add(pdata, data)

		type_description = "0x1e00"
		
	elseif packettype == 0x1f00 then
		-- no read
		
		type_description = "0x1f00"

	elseif packettype == 0x2e00 then
		-- no read

		type_description = "0x2e00"
		
	else
		error = true
		type_description = string.format("Unknown packettype 0x%04x", packettype)
	end

	-- setting CR3 summary data into the info column in the UI
	padding = string.rep(' ', 40 - type_description:len())
	-- pinfo.cols.info = string.format("%s%sRegister: 0x%04x, Type: 0x%04x, Bytes: 0x%04x", type_description, padding, reg, packettype, cr3len + 2)
	pinfo.cols.info = string.format("Register 0x%04x: %s%s", reg, type_description, "")

	return
end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol tcp:789
tcp_table:add(789,cr3_proto)
