--------------------------------------------------------------------------------
-- Sample code is MIT licensed, see https://coronalabs.com/links/code/license
-- Copyright (C) 2016 Corona Labs Inc. All Rights Reserved.
--------------------------------------------------------------------------------

--
-- Demonstrates simple but secure AES256 encryption
--

local json = require "json"
local openssl = require( "plugin.openssl" )

local g = display.newGroup()
 
local msg = "OpenSSL Encryption"

local title = display.newText( msg, 0, 0, native.systemFont, 30 )
title.anchorY = 0
title.x = display.contentWidth / 2
title.y = 10
title:setFillColor( 233/255, 137/255, 38/255 )

g:insert(title)

local log = native.newTextBox( display.actualContentWidth / 2, (display.actualContentHeight - 100) / 2, display.actualContentWidth-10, 400)
log.anchorY = 0
log.size = 10
log.x = display.contentWidth / 2
log.y = title.y + title.height + 10

g:insert(log)

local origPrint = Runtime._G.print

Runtime._G.print = function(...)
	log.text = log.text .. "\n" .. string.format("%.5g: ", system.getTimer())

	for _, k in ipairs({...}) do
		log.text = log.text .. " " .. tostring(k)
	end

	origPrint(...)
end

---------------------------------------------------------------------------
 
local openssl = require( "plugin.openssl" )

local aes256cbc = openssl.get_cipher( "aes-256-cbc" )

local lua_openssl_version, lua_version, openssl_version = openssl.version()
print( "lua-openssl version: " .. lua_openssl_version, lua_version, openssl_version )

print("openssl:" ,json.prettify(openssl))

local mime = require( "mime" )
 
local testString = "Test String"
local testKey = "TestKey@#$"

local encryptedData = mime.b64( aes256cbc:encrypt( testString, testKey ) )
local decryptedData = aes256cbc:decrypt( mime.unb64( encryptedData ), testKey )
 
print( "Test String: " .. testString )
print("")
print( "Encrypted Text: " .. encryptedData )
print("")
print( "Decrypted Text: " .. decryptedData )

