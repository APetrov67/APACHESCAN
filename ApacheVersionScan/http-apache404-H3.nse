local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"


license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = shortport.http

action = function(host, port)
  local resp, redirect_url, title

  resp = http.get( host, port, stdnse.get_script_args(SCRIPT_NAME..".url") or "/404" )

  -- check for a redirect
  if resp.location then
    redirect_url = resp.location[#resp.location]
    if resp.status and tostring( resp.status ):match( "30%d" ) then
      return {redirect_url = redirect_url}, ("Did not follow redirect to %s"):format( redirect_url )
    end
  end

  if ( not(resp.body) ) then
    return
  end

  -- try and match title tags
  title = string.match(resp.body, "<[Hh][3][^>]*>([^<]*)</[Hh][3]>")

  local display_title = title

  if display_title and display_title ~= "" then
    display_title = string.gsub(display_title , "[\n\r\t]", "")
    if #display_title > 65 then
      display_title = string.sub(display_title, 1, 62) .. "..."
    end
  else
    display_title = "Site doesn't have a title"
    if ( resp.header and resp.header["content-type"] ) then
      display_title = display_title .. (" (%s)."):format( resp.header["content-type"] )
    else
      display_title = display_title .. "."
    end
  end

  local output_tab = stdnse.output_table()
  output_tab.title = title
  output_tab.redirect_url = redirect_url

  local output_str = display_title
  if redirect_url then
    output_str = output_str .. "\n" .. ("Requested resource was %s"):format( redirect_url )
  end

  return output_tab, output_str
end