local CP2CP_COMMAND = os.getenv("WIRESHARK_CP2CP_COMMAND") or "cp2cp"

local function is_cp2cp_available()
    local process = io.popen(string.format("which %s 2>/dev/null", CP2CP_COMMAND), "r")
    if not process then
        return false
    end
    local result = process:read("*a")
    process:close()
    return result ~= nil and result:match("%S") ~= nil
end

if not is_cp2cp_available() then
    error(string.format("%s tool is not available in PATH or specified via $WIRESHARK_CP2CP_COMMAND. Please install or configure it.", CP2CP_COMMAND))
end

local chainpack_proto = Proto("chainpack-rpc-block", "Chainpack RPC Block Protocol")
local fields = {
    block_length = ProtoField.uint32("chainpack-rpc-block.block_length", "Block Length", base.DEC),
    payload_length = ProtoField.uint32("chainpack-rpc-block.payload_length", "Payload Length", base.DEC),
    protocol_type = ProtoField.string("chainpack-rpc-block.protocol_type", "Protocol Type"),
    payload = ProtoField.string("chainpack-rpc-block.payload", "Payload"),
    message_type = ProtoField.string("chainpack-rpc-block.message_type", "Message Type"),
    meta_type_id = ProtoField.int32("chainpack-rpc-block.meta_type_id", "MetaTypeId", base.DEC),
    request_id = ProtoField.int32("chainpack-rpc-block.request_id", "RequestId", base.DEC),
    shv_path = ProtoField.string("chainpack-rpc-block.shv_path", "ShvPath"),
    method = ProtoField.string("chainpack-rpc-block.method", "Method")
}
chainpack_proto.fields = fields

local CP2CP_EXIT_CODES = {
    SUCCESS = 0,
    UNRECOVERABLE_ERROR = 1,
    NOT_ENOUGH_DATA = 2,
    INTERNAL_ERROR = 3
}

local function run_cp2cp(payload)
    local tmpfile = os.tmpname()
    local command = string.format("%s --chainpack-rpc-block < %s", CP2CP_COMMAND, tmpfile)

    local file = io.open(tmpfile, "wb")
    if not file then
        return nil, "Failed to create temporary file"
    end
    file:write(payload:raw())
    file:close()

    local process = io.popen(command, "r")
    if not process then
        os.remove(tmpfile)
        return nil, "Failed to run cp2cp"
    end

    local output = process:read("*a")
    local _, _, exit_code = process:close()
    os.remove(tmpfile)

    return output, exit_code
end

local function parse_angle_brackets(content, payload_subtree)
    local pattern = "(%d+):([^,]+)"
    local rqid = nil
    local method = nil

    for attribute, value in content:gmatch(pattern) do
        local attr_id = tonumber(attribute)
        if attr_id == 1 then
            payload_subtree:add(fields.meta_type_id, tonumber(value))
        elseif attr_id == 8 then
            rqid = tonumber(value)
            payload_subtree:add(fields.request_id, rqid)
        elseif attr_id == 9 then
            local shv_path = value:sub(2, -2)
            payload_subtree:add(fields.shv_path, shv_path)
        elseif attr_id == 10 then
            method = value:sub(2, -2)
            payload_subtree:add(fields.method, method)
        end
    end

    if rqid and method then
        payload_subtree:set_text(string.format("RPC Request (%s)", rqid))
    elseif rqid and not method then
        payload_subtree:set_text(string.format("RPC Response (%s)", rqid))
    elseif not rqid and method then
        payload_subtree:set_text(string.format("RPC Signal (%s)", method))
    else
        payload_subtree:set_text("Unknown RPC message type")
    end

end

local function dissect_chainpack_message(tvb, pinfo, tree)
    local payload = tvb:bytes()
    local output, exit_code = run_cp2cp(payload)

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

    local block_length = tonumber(lines[1])
    local payload_length = tonumber(lines[2])
    local protocol_type = lines[3]
    local payload_data = table.concat(lines, "\n", 4)

    local block_subtree = tree:add(tvb(0, block_length), "Chainpack RPC Block Message")
    block_subtree:add(fields.block_length, tvb(0, block_length), block_length)
    block_subtree:add(fields.payload_length, tvb(0, block_length - payload_length), payload_length)
    block_subtree:add(fields.protocol_type, tvb(block_length - payload_length, 1), protocol_type)

    local payload_subtree = block_subtree:add(fields.payload, tvb(block_length - payload_length + 1), payload_data)

    local angle_brackets_content = payload_data:match("<([^>]+)>")
    if angle_brackets_content then
        parse_angle_brackets(angle_brackets_content, payload_subtree)
        payload_subtree:append_text(' ' .. payload_data)
    end

    return block_length
end

function chainpack_proto.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "CHAINPACK-RPC-BLOCK"

    local bytes_consumed = 0
    while bytes_consumed < tvb:len() do
        local input = tvb(bytes_consumed):tvb()
        local segment_length, block_length = dissect_chainpack_message(input, pinfo, tree)
        if segment_length == 0 then
            pinfo.desegment_len = block_length and block_length - input:len() or DESEGMENT_ONE_MORE_SEGMENT
            pinfo.desegment_offset = bytes_consumed
            return
        end

        bytes_consumed = bytes_consumed + segment_length
    end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(3755, chainpack_proto)
