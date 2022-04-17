local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"


license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = shortport.http

action = function(host, port)
  local resp, title

  local rand = math.random(1,500)
  resp = http.get( host, port, stdnse.get_script_args(SCRIPT_NAME..".url") or "/rand" )

  -- check status
  if resp then
    if( not(resp.status and tostring(resp.status):match( "404" ))) then
    return print("THIS REQUEST RETURNED A STATUS OTHER THAN 404")      
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
  else
   print("No version Apache Tomcat")
  end

  local output_str = display_title
  return  output_str
end