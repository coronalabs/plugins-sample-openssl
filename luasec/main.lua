--------------------------------------------------------------------------------
-- Sample code is MIT licensed, see http://www.coronalabs.com/links/code/license
-- Copyright (C) 2013 Corona Labs Inc. All Rights Reserved.
--------------------------------------------------------------------------------
--
-- To test this client-side code, use this server:
--
--		openssl s_server \
--		-key path/to/my/private_key.pem \
--		-cert path/to/my/signed_public_key_certificate.pem \
--		-accept 64001 -www

print( "lua-openssl secure socket test start." )

local openssl = require('plugin.openssl')
local socket = require('socket')
local plugin_luasec_ssl = require('plugin_luasec_ssl')

lua_openssl_version, lua_version, openssl_version = openssl.version()
print( "lua-openssl version: " .. lua_openssl_version, lua_version, openssl_version )

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

-- TLS/SSL client parameters (omitted)
local params =
{
	mode = "client",
	protocol = "tlsv1",
	verify = "none",
	options = "all",
}

local conn = socket.tcp()

local server_address = "10.3.3.106"
local server_port = 64001

local result, error = conn:connect( server_address, server_port )
if result then
	-- We're connected.
else
	print( "Failed to connect to: " .. server_address .. ":" .. tostring( server_port ) .. " Error: " .. error )
	return
end

-- TLS/SSL initialization
conn = plugin_luasec_ssl.wrap(conn, params)
conn:dohandshake()
--
conn:send( "GET / HTTP/1.0\n\n" )

local data, status, partial_data = conn:receive("*a")
if data then
	print( data )
end
if partial_data then
	print( partial_data )
end

conn:close()

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

print( "lua-openssl secure socket test done." )
