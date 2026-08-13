-- SMS Media over TCP (smserver, default port 8060)
-- Frame: 8-byte header ('$' | type | seq_be16 | len_be32) + body
--   type 0=JSON, 1=VIDEO (int64 frame_id + Annex-B), 2=AUDIO
-- Dissect + Tools menu export of video Annex-B (.h264 / .h265)
-- Compatible with Wireshark 4.4 / 4.6+ (Lua 5.4)
-- Protocol reference: mult-player/doc/SMS流交互协议.md
------------------------------------------------------------------------------------------------
do
    local proto_sms = Proto("sms_media", "SMS Media (TCP)")

    local media_type_vals = {
        [0] = "JSON",
        [1] = "VIDEO",
        [2] = "AUDIO",
    }

    local f_flag = ProtoField.uint8("sms_media.flag", "Flag", base.HEX)
    local f_type = ProtoField.uint8("sms_media.type", "Media type", base.DEC, media_type_vals)
    local f_seq = ProtoField.uint16("sms_media.seq", "Sequence", base.DEC)
    local f_len = ProtoField.uint32("sms_media.length", "Body length", base.DEC)
    local f_json = ProtoField.string("sms_media.json", "JSON")
    local f_codec = ProtoField.string("sms_media.codec", "Video codec")
    local f_frame_id = ProtoField.bytes("sms_media.video.frame_id", "Frame ID", base.SPACE)
    local f_annexb = ProtoField.bytes("sms_media.video.annexb", "Annex-B payload")
    local f_audio = ProtoField.bytes("sms_media.audio", "Audio payload")
    local f_body = ProtoField.bytes("sms_media.body", "Body")

    proto_sms.fields = {
        f_flag, f_type, f_seq, f_len, f_json, f_codec,
        f_frame_id, f_annexb, f_audio, f_body,
    }

    -- stream_key -> "H264" / "H265" learned from JSON live/play response
    local stream_codec_map = {}

    local prefs = proto_sms.prefs
    prefs.tcp_port = Pref.uint("TCP port", 8060, "Default SMS media TCP port (smserver)")
    prefs.tcp_ports = Pref.range("Additional TCP ports", "", "Extra ports dissected as SMS Media", 65535)
    prefs.export_ext = Pref.string("Export extension", "auto",
        "Default export extension: auto | h264 | h265 | hevc | bin")

    local bit = bit
    if bit == nil then
        local ok, mod = pcall(require, "bit32")
        if ok then bit = mod end
    end
    if bit == nil then
        local ok, mod = pcall(require, "bit")
        if ok then bit = mod end
    end
    if bit == nil then
        error("tcp_sms: bit operations library not available")
    end

    local h264_dis = Dissector.get("h264")
    local h265_dis = Dissector.get("h265")

    local function stream_key(pinfo)
        return string.format("%s:%s>%s:%s",
            tostring(pinfo.src), tostring(pinfo.src_port),
            tostring(pinfo.dst), tostring(pinfo.dst_port))
    end

    local function reverse_key(pinfo)
        return string.format("%s:%s>%s:%s",
            tostring(pinfo.dst), tostring(pinfo.dst_port),
            tostring(pinfo.src), tostring(pinfo.src_port))
    end

    local function learn_codec_from_json(json_str, pinfo)
        if not json_str then
            return
        end
        -- crude extract: "codec_type":"H264" / H265 / HEVC
        local codec = string.match(json_str, '"codec_type"%s*:%s*"([%w_]+)"')
        if not codec then
            return
        end
        codec = string.upper(codec)
        if codec == "HEVC" then
            codec = "H265"
        end
        if codec == "H264" or codec == "H265" then
            -- server→client video uses this direction; also remember reverse for lookup
            stream_codec_map[stream_key(pinfo)] = codec
            stream_codec_map[reverse_key(pinfo)] = codec
        end
    end

    local function guess_codec_from_annexb(payload)
        -- Look at first NAL after start code
        if not payload or #payload < 5 then
            return nil
        end
        local i = 1
        while i + 4 <= #payload do
            local b0, b1, b2, b3 = string.byte(payload, i, i + 3)
            local sc = 0
            if b0 == 0 and b1 == 0 and b2 == 1 then
                sc = 3
            elseif b0 == 0 and b1 == 0 and b2 == 0 and b3 == 1 then
                sc = 4
            end
            if sc > 0 then
                local nal0 = string.byte(payload, i + sc)
                if not nal0 then
                    return nil
                end
                -- H265: forbidden_zero_bit + nal_unit_type in high bits of first byte
                local h265_type = bit.rshift(bit.band(nal0, 0x7E), 1)
                local h264_type = bit.band(nal0, 0x1F)
                -- VPS(32)/SPS(33)/PPS(34) strongly indicate H.265
                if h265_type == 32 or h265_type == 33 or h265_type == 34 then
                    return "H265"
                end
                -- H264 SPS(7)/PPS(8)/IDR(5)/non-IDR(1)
                if h264_type == 7 or h264_type == 8 or h264_type == 5 or h264_type == 1 then
                    return "H264"
                end
                return nil
            end
            i = i + 1
            if i > 64 then
                break
            end
        end
        return nil
    end

    local function dissect_one(tvb, pinfo, tree, offset)
        local media_type = tvb(offset + 1, 1):uint()
        local body_len = tvb(offset + 4, 4):uint()
        local total = 8 + body_len
        local pdu_tvb = tvb(offset, total)

        local subtree = tree:add(proto_sms, pdu_tvb)
        subtree:add(f_flag, tvb(offset, 1))
        subtree:add(f_type, tvb(offset + 1, 1))
        subtree:add(f_seq, tvb(offset + 2, 2))
        subtree:add(f_len, tvb(offset + 4, 4))

        local type_name = media_type_vals[media_type] or "UNKNOWN"
        subtree:append_text(string.format(" %s (len=%d)", type_name, body_len))

        if body_len == 0 then
            return total
        end

        local body_off = offset + 8
        if media_type == 0 then
            local json_range = tvb(body_off, body_len)
            local json_str = json_range:string()
            subtree:add(f_json, json_range)
            learn_codec_from_json(json_str, pinfo)
            local codec = stream_codec_map[stream_key(pinfo)]
            if codec then
                subtree:add(f_codec, codec):set_generated()
            end
        elseif media_type == 1 then
            if body_len >= 8 then
                subtree:add(f_frame_id, tvb(body_off, 8))
                local annex_len = body_len - 8
                if annex_len > 0 then
                    local annex_tvb = tvb(body_off + 8, annex_len)
                    local annex_item = subtree:add(f_annexb, annex_tvb)
                    annex_item:append_text(string.format(" (%d bytes)", annex_len))

                    local codec = stream_codec_map[stream_key(pinfo)]
                        or stream_codec_map[reverse_key(pinfo)]
                        or guess_codec_from_annexb(annex_tvb:raw())
                    if codec then
                        subtree:add(f_codec, codec):set_generated()
                        stream_codec_map[stream_key(pinfo)] = codec
                    end

                    -- Best-effort NAL tree (may fail on partial/aggregated Annex-B)
                    if codec == "H265" and h265_dis then
                        pcall(function() h265_dis:call(annex_tvb:tvb(), pinfo, subtree) end)
                    elseif codec == "H264" and h264_dis then
                        pcall(function() h264_dis:call(annex_tvb:tvb(), pinfo, subtree) end)
                    end
                end
            else
                subtree:add(f_body, tvb(body_off, body_len))
            end
        elseif media_type == 2 then
            subtree:add(f_audio, tvb(body_off, body_len))
        else
            subtree:add(f_body, tvb(body_off, body_len))
        end

        return total
    end

    function proto_sms.dissector(tvb, pinfo, tree)
        local offset = 0
        local tvb_len = tvb:reported_length_remaining()
        if tvb_len < 1 then
            return 0
        end

        -- Require leading '$' for the first PDU in this tvb
        if tvb(0, 1):uint() ~= 0x24 then
            return 0
        end

        pinfo.cols.protocol = "SMS"
        local dissected = 0

        while offset < tvb_len do
            local remain = tvb_len - offset
            if remain < 8 then
                pinfo.desegment_offset = offset
                pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                return tvb_len
            end

            if tvb(offset, 1):uint() ~= 0x24 then
                -- lost sync; stop (avoid eating unrelated TCP data)
                break
            end

            local body_len = tvb(offset + 4, 4):uint()
            if body_len > 16 * 1024 * 1024 then
                break
            end
            local need = 8 + body_len
            if remain < need then
                pinfo.desegment_offset = offset
                pinfo.desegment_len = need - remain
                return tvb_len
            end

            dissect_one(tvb, pinfo, tree, offset)
            offset = offset + need
            dissected = dissected + 1
        end

        if dissected > 0 then
            pinfo.cols.info = string.format("SMS Media x%d", dissected)
        end
        return offset
    end

    local function looks_like_sms(tvb)
        if tvb:len() < 8 then
            return false
        end
        if tvb(0, 1):uint() ~= 0x24 then
            return false
        end
        local t = tvb(1, 1):uint()
        if t > 2 then
            return false
        end
        local body_len = tvb(4, 4):uint()
        if body_len > 16 * 1024 * 1024 then
            return false
        end
        return true
    end

    local function heuristic_sms(tvb, pinfo, tree)
        if not looks_like_sms(tvb) then
            return false
        end
        proto_sms.dissector(tvb, pinfo, tree)
        return true
    end

    -- Port registration helpers
    local tcp_table = DissectorTable.get("tcp.port")
    local registered_ports = {}

    local function clear_ports()
        for port, _ in pairs(registered_ports) do
            tcp_table:remove(port, proto_sms)
        end
        registered_ports = {}
    end

    local function add_port(port)
        port = tonumber(port)
        if not port or port < 1 or port > 65535 then
            return
        end
        if registered_ports[port] then
            return
        end
        tcp_table:add(port, proto_sms)
        registered_ports[port] = true
    end

    local function parse_port_range(str)
        local ports = {}
        if not str or str == "" then
            return ports
        end
        string.gsub(tostring(str), '[^,]+', function(w)
            local pos = string.find(w, '-')
            if not pos then
                table.insert(ports, tonumber(w))
            else
                local a = tonumber(string.sub(w, 1, pos - 1))
                local b = tonumber(string.sub(w, pos + 1))
                if a and b and a <= b then
                    for p = a, b do
                        table.insert(ports, p)
                    end
                end
            end
        end)
        return ports
    end

    function proto_sms.init()
        stream_codec_map = {}
        clear_ports()
        add_port(prefs.tcp_port)
        for _, p in ipairs(parse_port_range(prefs.tcp_ports)) do
            add_port(p)
        end
    end

    proto_sms:register_heuristic("tcp", heuristic_sms)

    ---------------------------------------------------------------------------
    -- Export Annex-B video
    ---------------------------------------------------------------------------
    local function string_ends(s, e)
        return e == '' or string.sub(s, -string.len(e)) == e
    end

    local function get_temp_path()
        local tmp = os.getenv('HOME')
        if tmp == nil or tmp == '' then
            tmp = os.getenv('USERPROFILE')
            if tmp == nil or tmp == '' then
                tmp = persconffile_path('temp')
            else
                tmp = tmp .. "/wireshark_temp"
            end
        else
            tmp = tmp .. "/wireshark_temp"
        end
        return tmp
    end

    local function get_ffmpeg_path()
        local tmp = os.getenv('FFMPEG')
        if tmp == nil or tmp == '' then
            return ""
        end
        if not string_ends(tmp, "/bin/") and not string_ends(tmp, "\\bin\\") then
            tmp = tmp .. "/bin/"
        end
        return tmp
    end

    local f_annexb_field = Field.new("sms_media.video.annexb")
    local f_codec_field = Field.new("sms_media.codec")
    local filter_string = nil

    local function pick_extension(codec, pref_ext)
        local ext = string.lower(tostring(pref_ext or "auto"))
        if ext == "h264" or ext == "264" then
            return ".h264"
        end
        if ext == "h265" or ext == "hevc" or ext == "265" then
            return ".h265"
        end
        if ext == "bin" then
            return ".bin"
        end
        if codec == "H265" then
            return ".h265"
        end
        return ".h264"
    end

    local function export_sms_video()
        local tw = TextWindow.new("Export SMS Video to File")
        local pgtw

        local function twappend(str)
            tw:append(str)
            tw:append("\n")
        end

        local ffmpeg_path = get_ffmpeg_path()
        local temp_path = get_temp_path()
        local first_run = true
        local stream_infos = nil

        local list_filter
        if filter_string == nil or filter_string == '' then
            list_filter = "sms_media.video.annexb"
        elseif string.find(filter_string, "sms_media") then
            list_filter = filter_string
        else
            list_filter = "sms_media.video.annexb && " .. filter_string
        end
        twappend("Listener filter: " .. list_filter)
        twappend("Tip: apply display filter e.g. tcp.port==8060 && ip.addr==x.x.x.x before export.")
        twappend("")

        local tap = Listener.new("frame", list_filter)

        local function get_stream_info(pinfo, codec)
            local key = "from_" .. tostring(pinfo.src) .. "_" .. tostring(pinfo.src_port)
                .. "_to_" .. tostring(pinfo.dst) .. "_" .. tostring(pinfo.dst_port)
            key = key:gsub(":", ".")
            local info = stream_infos[key]
            if not info then
                info = {}
                info.codec = codec or stream_codec_map[stream_key(pinfo)] or "H264"
                info.ext = pick_extension(info.codec, prefs.export_ext)
                info.filename = key .. info.ext
                if not Dir.exists(temp_path) then
                    Dir.make(temp_path)
                end
                info.filepath = temp_path .. "/" .. info.filename
                local msg
                info.file, msg = io.open(info.filepath, "wb")
                if msg then
                    twappend("io.open " .. info.filepath .. ", error " .. msg)
                end
                info.counter = 0
                info.counter2 = 0
                info.bytes = 0
                stream_infos[key] = info
                twappend(string.format(
                    "Ready: %s:%s -> %s:%s  codec=%s  file=[%s]",
                    tostring(pinfo.src), tostring(pinfo.src_port),
                    tostring(pinfo.dst), tostring(pinfo.dst_port),
                    info.codec, info.filename))
            elseif codec and info.codec ~= codec then
                info.codec = codec
            end
            return info
        end

        function tap.packet(pinfo, tvb)
            if stream_infos == nil then
                return
            end
            local annexs = { f_annexb_field() }
            local codecs = { f_codec_field() }
            local codec_val = nil
            if codecs[1] then
                codec_val = tostring(codecs[1].value or codecs[1].display or "")
                if codec_val == "" then
                    codec_val = nil
                end
            end

            for _, af in ipairs(annexs) do
                if af and af.len and af.len > 0 then
                    local info = get_stream_info(pinfo, codec_val)
                    local raw = af.range:raw()
                    if first_run then
                        info.counter = info.counter + 1
                        if not codec_val then
                            local g = guess_codec_from_annexb(raw)
                            if g then
                                info.codec = g
                            end
                        end
                    else
                        if info.file then
                            info.file:write(raw)
                            info.bytes = info.bytes + #raw
                            info.counter2 = info.counter2 + 1
                            if info.counter > 0 and info.counter2 < info.counter then
                                pgtw:update(info.counter2 / info.counter)
                            end
                        end
                    end
                end
            end
        end

        function tap.reset()
        end

        local function close_all_files()
            twappend("")
            local index = 0
            local no_streams = true
            if stream_infos then
                for _, stream in pairs(stream_infos) do
                    if stream and stream.file then
                        stream.file:flush()
                        stream.file:close()
                        stream.file = nil
                        index = index + 1
                        twappend(string.format(
                            "%d: [%s] OK  frames=%d bytes=%d codec=%s",
                            index, stream.filename, stream.counter2, stream.bytes, stream.codec))
                        local filepath = stream.filepath
                        local filename = stream.filename
                        local play_fmt = (stream.codec == "H265") and "hevc" or "h264"
                        tw:add_button("Play " .. index, function()
                            twappend("ffplay -f " .. play_fmt .. " -autoexit " .. filename)
                            os.execute(ffmpeg_path .. "ffplay -f " .. play_fmt
                                .. " -x 640 -y 480 -autoexit " .. filepath)
                        end)
                        no_streams = false
                    end
                end
            end
            if no_streams then
                twappend("No SMS video frames found.")
                twappend("Check: TCP port preference (default 8060), Decode As, or heuristic.")
                twappend("Also try display filter: sms_media")
            else
                tw:add_button("Browser", function() browser_open_data_file(temp_path) end)
            end
        end

        tw:set_atclose(function()
            tap:remove()
            if Dir.exists(temp_path) then
                Dir.remove_all(temp_path)
            end
        end)

        local function do_export()
            pgtw = ProgDlg.new("Export SMS Video", "Dumping Annex-B to file...")
            first_run = true
            stream_infos = {}
            retap_packets()
            first_run = false
            retap_packets()
            close_all_files()
            pgtw:close()
            stream_infos = nil
        end

        tw:add_button("Export All", function()
            do_export()
        end)

        tw:add_button("Set Filter", function()
            tw:close()
            new_dialog("SMS Export Filter", function(str)
                filter_string = str
                export_sms_video()
            end, "Filter")
        end)
    end

    local function dialog_default()
        filter_string = get_filter()
        export_sms_video()
    end

    register_menu("Video/Export SMS Video (H264/H265)", dialog_default, MENU_TOOLS_UNSORTED)
end
