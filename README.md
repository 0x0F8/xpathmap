##xpathmap

```
usage: xpathmap [-h] -u URL [-X] [-x PROXY] [-mr MATCH_REGEX] [-mh MATCH_HEADER] [-mc MATCH_CODE] [-ml MATCH_LINES] [-ms MATCH_SIZE] [-mw MATCH_WORDS] [-p PARAMS] [-d DATA] [-j] -i INJECT [-t INJECT_TYPE] [-H HEADER [HEADER ...]] [-o OUTPUT] [-oj]  
  
XML XPath exploitation  
  
options:  
  -h, --help            show this help message and exit  
  -u URL, --url URL     the target URL  
  -X, --post            Send requests as POST  
  -x PROXY, --proxy PROXY  
                        Proxy requests to this URL  
  -mr MATCH_REGEX, --match-regex MATCH_REGEX  
                        manually match this regex in the response body  
  -mh MATCH_HEADER, --match-header MATCH_HEADER  
                        manually match this string in the response header [name:value]  
  -mc MATCH_CODE, --match-code MATCH_CODE  
                        manually match this HTTP status code  
  -ml MATCH_LINES, --match-lines MATCH_LINES  
                        manually match this number of lines in the response body  
  -ms MATCH_SIZE, --match-size MATCH_SIZE  
                        manually match this response body size  
  -mw MATCH_WORDS, --match-words MATCH_WORDS  
                        manually match this number of words in the response body  
  -p PARAMS, --params PARAMS  
                        the GET parameters to send [p1,p2,p3,...]  
  -d DATA, --data DATA  the POST parameters to send, defaults to url-encoded [p1,p2,p3,...]  
  -j, --json            send POST data as json  
  -i INJECT, --inject INJECT  
                        the parameter name to inject  
  -t INJECT_TYPE, --inject-type INJECT_TYPE  
                        the type of parameter to inject, defaults to params for GET and data for POST [data|params]  
  -H HEADER [HEADER ...], --header HEADER [HEADER ...]  
                        send request header [name:value]  
  -o OUTPUT, --output OUTPUT  
                        output dumps to this folder instead of the config folder, defaults to CSV  
  -oj, --output-json    output dumps as JSON  
```
