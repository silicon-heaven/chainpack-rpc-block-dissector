-- Declare the Chainpack-RPC-Block protocol
local chainpack_proto = Proto("chainpack-rpc-block", "Chainpack RPC Block Protocol")

-- Define the fields for the protocol
local fields = {
    block_length = ProtoField.uint32("chainpack-rpc-block.block_length", "Block Length", base.DEC),
    payload_length = ProtoField.uint32("chainpack-rpc-block.payload_length", "Payload Length", base.DEC),
    protocol_type = ProtoField.string("chainpack-rpc-block.protocol_type", "Protocol Type"),
    payload = ProtoField.string("chainpack-rpc-block.payload", "Payload")
}

chainpack_proto.fields = fields

-- Exit codes for cp2cp
local CP2CP_EXIT_CODES = {
    SUCCESS = 0,
    UNRECOVERABLE_ERROR = 1,
    NOT_ENOUGH_DATA = 2,
    INTERNAL_ERROR = 3
}

-- Function to decode Chainpack payload using cp2cp tool
local function run_cp2cp(payload)
    local tmpfile = os.tmpname()
    local command = string.format("cp2cp --chainpack-rpc-block < %s", tmpfile)

    -- Write payload to temporary file
    local file = io.open(tmpfile, "wb")
    if not file then
        return nil, "Failed to create temporary file"
    end
    file:write(payload:raw())
    file:close()

    -- Execute cp2cp
    local process = io.popen(command, "r")
    if not process then
        os.remove(tmpfile)
        return nil, "Failed to run cp2cp"
    end

    local output = process:read("*a")
    local _, _, exit_code = process:close()

    -- Clean up temporary file
    os.remove(tmpfile)

    return output, exit_code
end

-- Function to dissect a single Chainpack message
local function dissect_chainpack_message(tvb, pinfo, tree)
    -- Extract the payload
    local payload = tvb:bytes()
    local output, exit_code = run_cp2cp(payload)

    -- Parse the cp2cp output
    local lines = {}
    for line in output:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end

    if exit_code == CP2CP_EXIT_CODES.UNRECOVERABLE_ERROR then
        tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Unrecoverable error in message")
        return tvb:len()
    elseif exit_code == CP2CP_EXIT_CODES.NOT_ENOUGH_DATA then
        local block_length = tonumber(lines[1])
        return 0, block_length
    elseif exit_code == CP2CP_EXIT_CODES.INTERNAL_ERROR then
        tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Internal error in cp2cp")
        return 0
    elseif exit_code ~= CP2CP_EXIT_CODES.SUCCESS then
        tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Unknown error")
        return 0
    end

    if #lines < 3 then
        tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Invalid cp2cp output")
        return 0
    end

    -- Extract fields from cp2cp output
    local block_length = tonumber(lines[1])
    local payload_length = tonumber(lines[2])
    local protocol_type = lines[3]
    local payload_data = table.concat(lines, "\n", 4)

    -- Add fields to the protocol tree
    local subtree_item = tree:add(tvb(0, block_length), "Chainpack RPC Block Message")
    subtree_item:add(fields.block_length, tvb(0, block_length), block_length)
    subtree_item:add(fields.payload_length, tvb(0, block_length - payload_length), payload_length)
    subtree_item:add(fields.protocol_type, tvb(block_length - payload_length, 1), protocol_type)
    subtree_item:add(fields.payload, tvb(block_length - payload_length + 1), payload_data)

    return block_length
end

-- Main dissector function
function chainpack_proto.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "CHAINPACK-RPC-BLOCK"

    -- Reassemble fragmented TCP segments
    local bytes_consumed = 0
    while bytes_consumed < tvb:len() do
        local input = tvb(bytes_consumed):tvb()
        local segment_length, block_length = dissect_chainpack_message(input, pinfo, tree)
        if segment_length == 0 then
            -- Wait for more data
            pinfo.desegment_len = block_length and block_length - input:len() or DESEGMENT_ONE_MORE_SEGMENT
            pinfo.desegment_offset = bytes_consumed
            return
        end

        bytes_consumed = bytes_consumed + segment_length
    end
end

-- Register the dissector to the default TCP port for Chainpack (3755)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(3755, chainpack_proto)
