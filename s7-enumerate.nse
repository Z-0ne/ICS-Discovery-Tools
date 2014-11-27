--
-- required packages for this script
--
-- plcscan.org Fix
-- Fix Support S7-300/400 and S7-1200 and S7 Series Unknown Devices
-- Last change 2014-11-14 add Support S7-1200
-- Last change 2014-11-26 add enumerates block functions number
--
local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates Siemens S7 PLC Devices and collects their device information. This
NSE is based off PLCScan that was developed by Positive Research and
Scadastrangelove (https://code.google.com/p/plcscan/). This script is meant to
provide the same functionality as PLCScan inside of Nmap. Some of the
information that is collected by PLCScan was not ported over to this NSE, this
information can be parsed out of the packets that are received.

Thanks to Positive Research, and Dmitry Efanov for creating PLCScan
]]

author = "Stephen Hilt (Digital Bond)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}

---
-- @usage
-- nmap -sP --script s7-discover.nse -p 102 <host/s>
--
-- @output
--102/tcp open  Siemens S7 315 PLC
--| s7-discover:
--|   Basic Hardware: 6ES7 315-2AG10-0AB0
--|   System Name: SIMATIC 300(1)
--|   Copyright: Original Siemens Equipment
--|   Version: 2.6.9
--|   Module Type: CPU 315-2 DP
--|   Module: 6ES7 315-2AG10-0AB0
--|_  Serial Number: S C-X4U421302009
--| ----------------------------------  
--|   Blocks Name: Count(Num)
--|   OB: 9
--|   FB: 0
--|   FC: 19
--|   DB: 18
--|   SDB: 17
--|   SFC: 71
--|   SFB: 20
--
--
-- @output
--102/tcp open  Siemens S7 1200 PLC
-- s7-enumerate:
--    Module: 6ES7 214-1AE30-0XB0
--    Basic Hardware: 6ES7 214-1AE30-0XB0
--    Version: 2.2.0
--
-- @xmloutput
--<elem key="Basic Hardware">6ES7 315-2AG10-0AB0</elem>
--<elem key="System Name">SIMATIC 300(1)</elem>
--<elem key="Copyright">Original Siemens Equipment</elem>
--<elem key="Version">2.6.9</elem>
--<elem key="Object Name">SimpleServer</elem>
--<elem key="Module Type">CPU 315-2 DP</elem>
--<elem key="Module">6ES7 315-2AG10-0AB0</elem>
--<elem key="Serial Number">S C-X4U421302009</elem>
--<elm key="Plant Identification"></elem>


-- port rule for devices running on TCP/102
portrule = shortport.port_or_service(102, "iso-tsap", "tcp")

---
-- Function to send and receive the S7COMM Packet
--
-- First argument is the socket that was created inside of the main Action
-- this will be utilized to send and receive the packets from the host.
-- the second argument is the query to be sent, this is passed in and is created
-- inside of the main action.
-- @param socket the socket that was created in Action.
-- @param query the specific query that you want to send/receive on.
function send_receive(socket, query)
  local sendstatus, senderr = socket:send(query)
  if(sendstatus == false) then
    return "Error Sending S7COMM"
  end
  -- receive response
  local rcvstatus,response = socket:receive()
  if(rcvstatus == false) then
    return "Error Reading S7COMM"
  end
  return response
end

---
-- Function to parse the first SZL Request response that was received from the S7 PLCC
--
-- First argument is the socket that was created inside of the main Action
-- this will be utilized to send and receive the packets from the host.
-- the second argument is the query to be sent, this is passed in and is created
-- inside of the main action.
-- @param response Packet response that was received from S7 host.
-- @param host The host hat was passed in via Nmap, this is to change output of host/port
-- @param port The port that was passed in via Nmap, this is to change output of host/port
-- @param output Table used for output for return to Nmap
function parse_response(response, host, port, output)
  -- unpack the protocol ID
  local pos, value = bin.unpack("C", response, 8)
  -- unpack the second byte of the SZL-ID
  local pos, szl_id = bin.unpack("C", response, 31)
  -- set the offset to 0
  local offset = 0
  -- if the protocol ID is 0x32
  if (value == 0x32) then
    local pos
    -- unpack the module information
    pos, output["Module"] = bin.unpack("z", response, 44)
    -- unpack the basic hardware information
    pos, output["Basic Hardware"] = bin.unpack("z", response, 72)
    -- set version number to 0
    local version = 0
    -- parse version number
    local pos, char1,char2,char3 = bin.unpack("CCC", response, 123)
    -- concatenate string, or if string is nil make version number 0.0
    output["Version"] = table.concat({char1 or "0.0", char2, char3}, ".")
    -- return the output table
    return output
  else
    output = DescFlag(S7DescFlag)
    return output
  end
end

---
-- Function to parse the second SZL Request response that was received from the S7 PLC
--
-- First argument is the socket that was created inside of the main Action
-- this will be utilized to send and receive the packets from the host.
-- the second argument is the query to be sent, this is passed in and is created
-- inside of the main action.
-- @param response Packet response that was received from S7 host.
-- @param output Table used for output for return to Nmap
function second_parse_response(response, output)
  local offset = 0
  -- unpack the protocol ID
  local pos, value = bin.unpack("C", response, 8)
  -- unpack the second byte of the SZL-ID
  local pos, szl_id = bin.unpack("C", response, 31)
  -- if the protocol ID is 0x32
  if (value == 0x32) then
    -- if the szl-ID is not 0x1c
    if( szl_id ~= 0x1c ) then
      -- change offset to 4, this is where most ov valid PLCs will fall
      offset = 4
    end
    -- parse system name
    pos, output["System Name"] = bin.unpack("z", response, 40 + offset)
    -- parse module type
    pos, output["Module Type"] = bin.unpack("z", response, 74 + offset)
    -- parse serial number
    pos, output["Serial Number"] = bin.unpack("z", response, 176 + offset)
    -- parse plant identification
    pos, output["Plant Identification"] = bin.unpack("z", response, 108 + offset)
    -- parse copyright
    pos, output["Copyright"] = bin.unpack("z", response, 142 + offset)

    -- for each element in the table, if it is nil, then remove the information from the table
    for key,value in pairs(output) do
      if(string.len(output[key]) == 0) then
        output[key] = nil
      end
    end
    -- return output
    return output
  else
    output = DescFlag(S7DescFlag)
    return output
  end
end
---
--  Function to set the nmap output for the host, if a valid S7COMM packet
--  is received then the output will show that the port is open
--  and change the output to reflect an S7 PLC
--
-- @param host Host that was passed in via nmap
-- @param port port that S7COMM is running on
function set_nmap(host, port)
  --set port Open
  port.state = "open"
  -- set that detected an Siemens S7
  port.version.name = "iso-tsap"
  port.version.devicetype = "specialized"
  port.version.product = "Siemens S7 PLC"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")

end
---
--
-- if get fail SZL info output S7 protocol Flag
--
-- add S7 protocol Flag
--
--
function DescFlag(S7DescFlag)
  output = stdnse.output_table()
  local pos, protocol_head = bin.unpack("C", S7DescFlag, 1)
  if (protocol_head == 0x03) then
    output["Devices Type"] = 'Siemens S7 Series Devices'
    return output
  end
end
--
--
---
-- to parse the list block response
--
--
function parse_listblock_response(response, output)
  local block_type = {
  [56] = "OB",
  [69] = "FB",
  [67] = "FC",
  [65] = "DB",
  [66] = "SDB",
  [68] = "SFC",
  [70] = "SFB"
}
--  print "dev debug1"
  local pos, protocol_id = bin.unpack("C", response, 8)
  local pos, listlength = bin.unpack("C", response, 33)
  if (protocol_id == 0x32) then
--    print "dev debug2"
    if (listlength == 0x1c) then
--	  print "dev debug3"
      output["Blocks Name"] = "Count(Num)"
      local pos, fuc1 = bin.unpack("C", response, 35)
      local pos, count1 = bin.unpack("C", response, 37)
      output[block_type[fuc1]] = count1
      local pos, fuc2 = bin.unpack("C", response, 39)
      local pos, count2 = bin.unpack("C", response, 41)	
      output[block_type[fuc2]] = count2
      local pos, fuc3 = bin.unpack("C", response, 43)
      local pos, count3 = bin.unpack("C", response, 45)
      output[block_type[fuc3]] = count3
      local pos, fuc4 = bin.unpack("C", response, 47)
      local pos, count4 = bin.unpack("C", response, 49)
      output[block_type[fuc4]] = count4
      local pos, fuc5 = bin.unpack("C", response, 51)
      local pos, count5 = bin.unpack("C", response, 53)
      output[block_type[fuc5]] = count5
      local pos, fuc6 = bin.unpack("C", response, 55)
      local pos, count6 = bin.unpack("C", response, 57)
      output[block_type[fuc6]] = count6
      local pos, fuc7 = bin.unpack("C", response, 59)
      local pos, count7 = bin.unpack("C", response, 61)
      output[block_type[fuc7]] = count7
      return output
    else
      return output
    end
  else
    return output
  end
end

--
--
--
---
---
--  Action Function that is used to run the NSE. This function will send the initial query to the
--  host and port that were passed in via nmap. The initial response is parsed to determine if host
--  is a S7COMM device. If it is then more actions are taken to gather extra information.
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host,port)
  -- COTP packet with a dst of 102
  local COTP = bin.pack("H","0300001611e00000001400c1020100c2020" .. "102" .. "c0010a")
  -- COTP packet with a dst of 200
  local alt_COTP = bin.pack("H","0300001611e00000000500c1020100c2020" .. "200" .. "c0010a")
  -- setup the ROSCTR Packet
  local ROSCTR_Setup = bin.pack("H","0300001902f08032010000000000080000f0000001000101e0")
  -- setup the Read SZL information packet
  local Read_SZL = bin.pack("H","0300002102f080320700000000000800080001120411440100ff09000400110001")
  -- setup the first SZL request (gather the basic hardware and version number)
  local first_SZL_Request = bin.pack("H","0300002102f080320700000000000800080001120411440100ff09000400110001")
  -- setup the second SZL request
  local second_SZL_Request = bin.pack("H","0300002102f080320700000000000800080001120411440100ff090004001c0001")
  ---
  -- add S7-1200 packet and Block Functions Enumerates
  -- by Z-0ne   plcscan.org
  -- Based on S7COMM Protocol analysis plugin.
  --
  ---
  -- S7-1200 PLC usage Rack 0 Slot 1
  local COTP_0x0000 = bin.pack("H","0300001611e00000000100c0010ac1020100c2020301")
  -- Setup communication 0xf0
  local Setup_comm = bin.pack("H","0300001902f080320100000c0000080000f0000001000101e0")
  -- Request SZL functions Read SZL ID=0X0011
  local Req_SZL_0x0011 = bin.pack("H","0300002102f080320700000d00000800080001120411440100ff09000400110000")
  -- Request Block Functions -> List blocks
  local Req_Block_fuc_list = bin.pack("H","0300001d02f0803207000025000008000400011204114301000a000000")
  --
  ---
  -- response is used to collect the packet responses
  local response
  -- output table for Nmap
  local output = stdnse.output_table()
  -- create socket for communications
  local sock = nmap.new_socket()
  -- connect to host
  local constatus,conerr = sock:connect(host,port)
  if not constatus then
    stdnse.print_debug(1,
      'Error establishing connection for %s - %s', host,conerr
      )
    return nil
  end
  -- send and receive the COTP Packet
  S7DescFlag  = send_receive(sock, COTP)
  -- unpack the PDU Type
  local pos, CC_connect_confirm = bin.unpack("C", S7DescFlag, 6)
  -- if PDU type is not 0xd0, then not a successful COTP connection
---
--  if ( CC_connect_confirm ~= 0xd0) then
--    return nil
--  end
---
    if ( CC_connect_confirm ~= 0xd0) then
---
--   add support S7 1200 packet send
---
      output = stdnse.output_table()
      local constatus,conerr = sock:connect(host,port)
      if not constatus then
        stdnse.print_debug(1,
          'Error establishing connection for %s - %s', host,conerr
          )
        return nil
      end
      S7DescFlag  = send_receive(sock, COTP_0x0000)
      local pos, CC_connect_confirm = bin.unpack("C", S7DescFlag, 6)
      if ( CC_connect_confirm ~= 0xd0) then
        stdnse.print_debug(1, "Not a successful COTP Packet_1200")
        output = DescFlag(S7DescFlag)
        return output
      end
      response = send_receive(sock, Setup_comm)
      local pos, protocol_id = bin.unpack("C", response, 8)
      if ( protocol_id ~= 0x32) then
        stdnse.print_debug(1, "Not a successful S7COMM Packet_1200")
        output = DescFlag(S7DescFlag)
        return output
      end
      response  = send_receive(sock, Req_SZL_0x0011)
      local pos, protocol_id = bin.unpack("C", response, 8)
      if ( protocol_id ~= 0x32) then
        stdnse.print_debug(1, "Not a successful S7COMM Packet_1200")
        output = DescFlag(S7DescFlag)
        return output
      end
      output = parse_response(response, host, port, output)
      response = send_receive(sock, Req_Block_fuc_list)
      output = parse_listblock_response(response, output)
      return output
--
---
  end
  -- send and receive the ROSCTR Setup Packet
  response  = send_receive(sock, ROSCTR_Setup)
  -- unpack the protocol ID
  local pos, protocol_id = bin.unpack("C", response, 8)
  -- if protocol ID is not 0x32 then return nil
---
  if ( protocol_id ~= 0x32) then
    stdnse.print_debug(1, "Not a successful S7COMM Packet")
--    return nil
  end
---  
  -- send and receive the READ_SZL packet
  response  = send_receive(sock, Read_SZL)
  local pos, protocol_id = bin.unpack("C", response, 8)
  -- if protocol ID is not 0x32 then return nil
---
  if ( protocol_id ~= 0x32) then
    stdnse.print_debug(1, "Not a successful S7COMM Packet")
--    return nil
  end
---
  -- send and receive the first SZL Request packet
  response  = send_receive(sock, first_SZL_Request)
  -- parse the response for basic hardware information
  output = parse_response(response, host, port, output)
  -- send and receive the second SZL Request packet
  response = send_receive(sock, second_SZL_Request)
  -- parse the response for more information
  output = second_parse_response(response, output)
--- 
  -- send and receive the list block request
  response = send_receive(sock, Req_Block_fuc_list)
  -- parse the response
  output = parse_listblock_response(response, output)
---  
  -- if nothing was parsed from the previous two responses
  if(output == nil) then
    -- re initialize the table
    output = stdnse.output_table()
    -- re connect to the device ( a RST packet was sent in the previous attempts)
    local constatus,conerr = sock:connect(host,port)
    if not constatus then
      stdnse.print_debug(1,
        'Error establishing connection for %s - %s', host,conerr
        )
      return nil
    end
    -- send and receive the alternate COTP Packet, the dst is 200 instead of 102( do nothing with result)
    S7DescFlag  = send_receive(sock, alt_COTP)
    local pos, CC_connect_confirm = bin.unpack("C", S7DescFlag, 6)
    -- if PDU type is not 0xd0, then not a successful COTP connection
---
    if ( CC_connect_confirm ~= 0xd0) then
      stdnse.print_debug(1, "Not a successful COTP Packet")
--      return nil
    end
---
    -- send and receive the packets as before.
    response  = send_receive(sock, ROSCTR_Setup)
    -- unpack the protocol ID
    local pos, protocol_id = bin.unpack("C", response, 8)
    -- if protocol ID is not 0x32 then return nil
---
    if ( protocol_id ~= 0x32) then
      stdnse.print_debug(1, "Not a successful S7COMM Packet")
--      return nil
    end
---
    response  = send_receive(sock, Read_SZL)
    -- unpack the protocol ID
    local pos, protocol_id = bin.unpack("C", response, 8)
    -- if protocol ID is not 0x32 then return nil
---
    if ( protocol_id ~= 0x32) then
      stdnse.print_debug(1, "Not a successful S7COMM Packet")
--      return nil
    end
---
    response  = send_receive(sock, first_SZL_Request)
    output = parse_response(response, host, port, "ONE", output)
    response = send_receive(sock, second_SZL_Request)
    output = parse_response(response, host, port, "TWO", output)
---	
    response = send_receive(sock, Req_Block_fuc_list)
    output = parse_listblock_response(response, output)
---
  end
  -- close the socket
  sock:close()
  
  -- If we parsed anything, then set the version info for Nmap
  if #output > 0 then
    set_nmap(host, port)
  end
  -- return output to Nmap
  return output

end

