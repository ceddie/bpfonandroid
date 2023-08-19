#!/usr/bin/env python3

import ctypes
import json
import logging
import os
import random
import re
import signal
import string
import subprocess
import sys
from os import listdir
from os.path import isdir, join, isfile
from datetime import datetime, timedelta
from bcc import BPF
import config
import threading

TYPE_MAP_ELEMENT_COUNTER = 0
NUM_TOTAL_PROBES = 0
INVERTED_LOOKUP_TABLE = None  # name -> address
STDOUT_ORIGINAL = None
LOGGER = None
GET_AAPI_FUNCTION_OFFSET_CACHE = dict()
GET_OFFSET_OF_SHARED_OBJECT_IN_ZYGOTE_CACHE = dict()
SYSCALL_PREFIX = BPF(text='').get_syscall_prefix().decode()
KPROBES_NOT_FOUND = set()
STATIC_INFO_LOOKUP_TABLE = {}  # address -> name, is_kprobe, is_special, event_handler (optional)
ERROR_EVENTS_OCCURRED = False
TIMER = None
CONFIG_DICT = None


class EventType(object):
    ENTRY_EVENT = 0
    RETURN_EVENT = 1
    FINAL_EVENT = 2
    INCOMPLETE_EVENT = 3
    ERROR_EVENT = 4


def generate_random_id(length):
    letters_and_digits = string.ascii_letters + string.digits
    random_id = ''.join((random.choice(letters_and_digits) for _ in range(length)))
    return random_id


def parse_arguments():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0].split('/')[-1]} <app package name | uid | apk-file>")
        exit()
    app_package_name_or_uid_or_apk_file = sys.argv[1]
    if app_package_name_or_uid_or_apk_file.isdigit():
        # UID
        app_uid = int(app_package_name_or_uid_or_apk_file)
        app_package_name = get_package_name_from_uid(app_uid)
    else:
        if app_package_name_or_uid_or_apk_file.split('.')[-1] == 'apk':
            # apk-file
            print(f"INFO: '{app_package_name_or_uid_or_apk_file}' is an apk-file. Trying to install...")
            app_package_name = get_package_name_from_apk(app_package_name_or_uid_or_apk_file)
            install_apk(app_package_name_or_uid_or_apk_file)
        else:
            # App package name
            app_package_name = app_package_name_or_uid_or_apk_file
        app_uid = get_uid_for_app_package_name(app_package_name)
    if not app_uid:
        print(f"Error: UID for App '{app_package_name}' not found!")
        exit(1)
    return app_package_name, app_uid


def set_up_logging(app_package_name, random_id):
    global LOGGER
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.FileHandler(f"{config.OUTPUT_FOLDER}/{random_id}-{app_package_name}.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    LOGGER = logging.getLogger()


def setup_event_stacks(b):
    event_stacks = b.get_table(b"event_stacks")
    for i in range(config.NUMBER_STACK_LEVELS):
        event_stacks[ctypes.c_int(i)] = ctypes.c_int(b.get_table(f"event_map_level{i}".encode()).get_fd())


def exec_oatdump(oat_file):
    LOGGER.info(f"Executing oatdump for '{oat_file}'. This may take a while...")
    env_variables =\
        "LD_LIBRARY_PATH=/apex/com.android.art/lib64/:/apex/com.android.i18n/lib64/:/apex/com.android.os.statsd/lib64/"
    cmd_str = f"{env_variables} /apex/com.android.art/bin/oatdump --oat-file={oat_file}"
    res = subprocess.run(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if config.DEBUG:
        LOGGER.info(res.stderr.decode())
    dump = res.stdout.decode()
    return dump


# tried oat_reader.py from https://github.com/lief-project/LIEF, but it didn't work properly
def parse_oatdump_output(oatdump):
    name_entry_returns_dict = dict()
    tokens = re.split(r"\(dex_method_idx=", oatdump)
    for i in range(1, len(tokens)):
        name = ' '.join(tokens[i-1].split('\n')[-1].strip().split(' ')[2:])
        res = re.findall(r"CODE: \(code_offset=(0x[0-9a-f]*) size=[0-9]*\)(?:\n\s*(NO CODE!))?", tokens[i])
        if res:
            offset_string, has_code = res[0]
            if has_code != 'NO CODE!':
                code_lines = tokens[i].split("CODE: (code_offset=")[1].split('\n')[1:-1]
                returns = []
                for line in code_lines:
                    pattern = re.compile("\s+(0x[0-9a-z]+):\s+[0-9A-Z]+\s+(.*)")
                    match = pattern.match(line)
                    if match and match.group(2).strip() == "ret":
                        returns.append(match.group(1))
                name_entry_returns_dict[name] = {"entry": offset_string, "returns": returns}
    return name_entry_returns_dict


def oat_file_to_cache_filename(oat_file):
    split = oat_file.split('/')
    name = split[-1]
    cache_filename = f"{name}.txt"
    return cache_filename


def read_cache(oat_file):
    cache_filename = oat_file_to_cache_filename(oat_file)
    if config.DEBUG:
        LOGGER.info(f"DEBUG: check cache for '{oat_file}' with cache filename: '{cache_filename}'...")
    cache_path = f'{config.CACHE_FOLDER}{cache_filename}'
    if os.path.isfile(cache_path):
        if config.DEBUG:
            LOGGER.info(f"DEBUG: found cachefile '{cache_filename}'")
        with open(cache_path, 'r') as file:
            return json.loads(file.read())
    else:
        if config.DEBUG:
            LOGGER.info(f"DEBUG: didn't find cachefile '{cache_filename}'")
        return None


def parse_tracing_segments(segments_file):
    tracing_sections = {'ENTRY': list(), 'RETURN': list()}
    with open(segments_file, 'r') as file:
        input_ = file.read()
        input_ = '}'.join(input_.split('}')[:-1])  # remove '}' of outer function
        # remove everything before '{' of outer function and split
        split = re.split(r'// ((?:ENTRY|RETURN) TRACING SEGMENT: \S*)', input_)[1:]
        i = 1
        while i < len(split):
            # every block is built like this:
            # // <type> TRACING SEGMENT: <label>
            # <segment>
            segment = '    ' + split[i].strip() + '\n'
            first_line = split[i - 1].strip().split(': ')
            type_ = first_line[0].split(' ')[0]
            label = first_line[1]
            tracing_sections[type_].append({'label': label, 'segment': segment})
            i += 2
    return tracing_sections


def write_cache(oat_file, res_dict):
    cache_filename = oat_file_to_cache_filename(oat_file)
    if not isdir(config.CACHE_FOLDER):
        LOGGER.info(f"WARNING: Folder '{config.CACHE_FOLDER}' for caching oatdumps does not exist.")
        return
    cache_path = f'{config.CACHE_FOLDER}{cache_filename}'
    if config.DEBUG:
        LOGGER.info("DEBUG: write cachefile")
    res_dict_filtered = dict()
    for k, v in res_dict.items():
        if len(v["returns"]) <= 5:
            res_dict_filtered[k] = v
    with open(cache_path, 'w') as file:
        file.write(json.dumps(res_dict_filtered, indent=4))


def get_offset_of_aapi_function_entry_and_returns_in_oat_file(function, oat_file):
    if oat_file in GET_AAPI_FUNCTION_OFFSET_CACHE:
        res_dict = GET_AAPI_FUNCTION_OFFSET_CACHE[oat_file]
    else:
        res_dict = read_cache(oat_file)
        if res_dict or res_dict == {}:
            GET_AAPI_FUNCTION_OFFSET_CACHE[oat_file] = res_dict
        else:
            res_dict = parse_oatdump_output(exec_oatdump(oat_file))
            write_cache(oat_file, res_dict)
    if function in res_dict:
        return int(res_dict[function]['entry'], 16), [int(a, 16) for a in res_dict[function]['returns']]
    else:
        LOGGER.info(f"ERROR: Offset of function \"{function}\" not found in file {oat_file}")
        return None, None


def get_uid_for_app_package_name(app_package_name):
    path = join(config.DATA_FOLDER, app_package_name)
    app_uid = get_gid_from_folder(path)
    return app_uid


def get_function_name_arguments_and_return_value_from_declaration(declaration, is_syscall=False):
    split_1 = declaration.split('(')
    split_2 = split_1[0].split(' ')
    if len(split_2) == 1:
        # declaration without return value
        name = split_2[0]
        ret = None
    else:
        # declaration with return value
        name = split_2[1]
        ret = split_2[0]
    if is_syscall:
        name = SYSCALL_PREFIX + name
    else:
        name = name
    if len(split_1) == 1:
        # declaration without arguments
        args = []
    else:
        # declaration with arguments
        args = list(map(lambda x: x.strip(), split_1[1][:-1].split(',')))
    # LOGGER.info(f"{ret} {name}({', '.join(args)})")
    return name, args, ret


def apply_uid_filter_code_block(app_uid, bpf_program):
    uid_filter_code = f'''// uid filter
    if (uid != {app_uid}){{
        return 0;
    }}
    '''
    if app_uid:
        bpf_program = bpf_program.replace('// UID_FILTER_BLOCK\n', uid_filter_code)
    else:
        bpf_program = bpf_program.replace('// UID_FILTER_BLOCK\n', '')
    return bpf_program


def apply_disable_android_api_return_tracing_block(bpf_program):
    bpf_program = bpf_program.replace('// DISABLE_ANDROID_API_RETURN_TRACING_BLOCK\n',
                                      "#define DISABLE_ANDROID_API_RETURN_TRACING\n")
    return bpf_program


def apply_enable_check_android_api_return_addresses_block(bpf_program):
    bpf_program = bpf_program.replace('// ENABLE_CHECK_ANDROID_API_RETURN_ADDRESS_BLOCK\n',
                                      "#define CHECK_ANDROID_API_RETURN_ADDRESSES\n")
    return bpf_program


def apply_function_addresses_block(bpf_program):
    function_addresses_block = ''
    for address, e in STATIC_INFO_LOOKUP_TABLE.items():
        name = e['name'].upper().replace(".", "__")
        name = name.replace("(", "_")
        name = name.replace(")", "_")
        name = name.replace("[", "_")
        name = name.replace("]", "_")
        name = name.replace(",", "_")
        name = name.replace("<", "_")
        name = name.replace(">", "_")
        name = name.replace("-", "_")
        name = name.replace("$", "_")
        function_addresses_block += f"#define ADR_{name}   0x{address:x}\n"

    bpf_program = bpf_program.replace('// FUNCTION_ADDRESSES_BLOCK\n', function_addresses_block)
    return bpf_program


def fill_type_map(b):
    global TYPE_MAP_ELEMENT_COUNTER
    type_map = b["type_map"]
    for k, v in STATIC_INFO_LOOKUP_TABLE.items():
        class TypeMapElement(ctypes.Structure):
            _fields_ = [
                ("is_kprobe", ctypes.c_uint),
                ("is_special", ctypes.c_uint),
                ("counter", ctypes.c_uint),
                ("expected_return_ips", ctypes.c_ulonglong * 5)
            ]
        type_map_element = TypeMapElement()
        type_map_element.is_kprobe = 1 if v['is_kprobe'] else 0
        type_map_element.is_special = 1 if v['is_special'] else 0
        type_map_element.counter = 0
        return_addresses = [0, 0, 0, 0, 0]
        if 'returns' in v:
            for i in range(len(v['returns'])):
                return_addresses[i] = int(v['returns'][i], 16)
        type_map_element.expected_return_ips = (ctypes.c_ulonglong * 5)(*return_addresses)
        # struct probe_type_t {
        #     u32 is_kprobe;
        #     u32 is_special;
        #     u32 counter;
        #     u64 expected_return_ip;
        # };
        try:
            type_map[ctypes.c_ulonglong(k)] = type_map_element
            TYPE_MAP_ELEMENT_COUNTER += 1
        except Exception as e:
            LOGGER.info(f"WARNING: Could not add {k} ({v['name']}) to type_map: {e}. (Counter {TYPE_MAP_ELEMENT_COUNTER})")


def get_package_name_from_apk(path):
    cmd_str = f"aapt dump badging {path} | grep -o -P \"package: name='.*?'\" | cut -c 16- | rev | cut -c 2- | rev"
    res = subprocess.run(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if 'aapt: command not found' in res.stderr.decode().strip():
        print(f"ERROR: Didn't find aapt. Is it installed correctly?")
        print("Hint: eadb # apt-get install aapt")
        print("")
        exit()
    elif "is neither a directory nor file" in res.stderr.decode():
        print(f"ERROR: Path '{path}' not found. Is the the apk-file there and the path correct?")
        print("")
        exit()
    else:
        return res.stdout.decode().strip()


def add_kprobe_to_lookup_table(function_declaration, is_syscall):
    name, _, _ = get_function_name_arguments_and_return_value_from_declaration(function_declaration, is_syscall)
    address = BPF.ksymname(name)
    if address == -1:
        LOGGER.info(f"ERROR: Address of function '{name}' not found.")
        KPROBES_NOT_FOUND.add(name)
    else:
        STATIC_INFO_LOOKUP_TABLE[address + 1] =\
            {'name': name, 'is_kprobe': True, 'is_special': is_syscall}  # special means syscall in case of kprobe


def get_package_name_from_uid(uid):
    folders = [f for f in listdir(config.DATA_FOLDER) if isdir(join(config.DATA_FOLDER, f))]
    res = None
    for f in folders:
        f_uid = get_gid_from_folder(join(config.DATA_FOLDER, f))
        if f_uid == int(uid):
            res = f
            break
    if not res:
        print(f"WARNING: No installed App with uid {uid} found. Maybe the App isn't installed yet?")
        res = 'unknown'
    return res


def get_gid_from_folder(path):
    cmd_str = f"stat -c '%g' {path}"
    res = subprocess.run(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if "No such file or directory" in res.stderr.decode():
        print(f"WARNING: Path '{path}' not found. Is the App installed and the folder mounted correctly?")
        print("Hint: run setup_avd.sh or setup_avd_production_build.sh in abd shell")
        return None
    else:
        return int(res.stdout.decode().strip())


def install_apk(path):
    if not isfile(path):
        print(f"ERROR: {path} is not a file!")
    cmd_str1 = f"cp {path} /data/local/tmp/"
    res = subprocess.run(cmd_str1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if 'No such file or directory' in res.stderr.decode().strip():
        print("Error: Folder '/data/local/tmp/' might not exist. Is it created and mounted correctly?")
        print("Hint: eadb # mkdir -p /data/local/tmp")
        print("      adb  # mount --bind /data/local/tmp /data/eadb/debian/data/local/tmp")
        print("")
        exit()
    print(res.stdout.decode().strip())
    file_name = path.split('/')[-1]
    cmd_str2 = f"pm install /data/local/tmp/{file_name}"
    res = subprocess.run(cmd_str2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if 'pm: command not found' in res.stderr.decode().strip():
        print("Error: Didn't find pm. Is PATH set up correctly?")
        print("Hint: eadb # PATH=$PATH:/system/bin/ main.py")
        print("")
        exit()
    print(res.stdout.decode().strip())
    print("")
    cmd_str3 = f"rm /data/local/tmp/{file_name}"
    subprocess.run(cmd_str3, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return None


def get_address_of_shared_object_in_zygote(path):
    if not isfile(path):
        LOGGER.info(f"ERROR: '{path}' is not a file!")
        return None
    if path in GET_OFFSET_OF_SHARED_OBJECT_IN_ZYGOTE_CACHE:
        return GET_OFFSET_OF_SHARED_OBJECT_IN_ZYGOTE_CACHE[path]
    else:
        cmd_str = f"pmap -p $(pidof zygote64) | grep '{path}' | head -n 1 | awk '{{print $1}}'"
        res = subprocess.run(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        res = int(res.stdout.decode().strip(), 16)
        GET_OFFSET_OF_SHARED_OBJECT_IN_ZYGOTE_CACHE[path] = res
        return res


def get_offset_of_function_entry_in_so_file(function, path):
    if not isfile(path):
        LOGGER.info(f"ERROR: '{path}' is not a file!")
        return None
    cmd_str = f"nm -D '{path}' | grep -E 'T {function}(@|$)' | head -n 1 | awk '{{print $1}}'"
    res = subprocess.run(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res = res.stdout.decode().strip()
    if res == '':
        LOGGER.info(f"ERROR: Address of function {function} in {path} not found.")
        return -1
    else:
        return int(res, 16)


def get_address_of_so_function_in_zygote(function, path):
    offset = get_address_of_shared_object_in_zygote(path)
    offset += get_offset_of_function_entry_in_so_file(function, path)
    return offset


def get_entry_and_returns_of_oat_function_in_zygote(function, path):
    base_address = get_address_of_shared_object_in_zygote(path)
    offset, returns = get_offset_of_aapi_function_entry_and_returns_in_oat_file(function, path)
    if offset:
        base_address += 0x1000
        return base_address + offset, [base_address + ret for ret in returns]
    else:
        return None, None
    # sym_res = b.sym(event.eip, event.pid, show_module=True)


# Read the config_dict and fill the lookup table. The keys are the absolute addresses of the functions.
def fill_lookup_table(config_dict):
    for syscall in config_dict['kprobes-syscalls']:
        add_kprobe_to_lookup_table(
            syscall['function'], is_syscall=True)  # special means syscall in case of kprobe

    for non_syscall in config_dict['kprobes-non-syscalls']:
        add_kprobe_to_lookup_table(
            non_syscall['function'], is_syscall=False)  # special means syscall in case of kprobe

    for so_func in config_dict['uprobes-so']:
        so_file = so_func['so_file']
        function = so_func['function']
        name, _, _ = get_function_name_arguments_and_return_value_from_declaration(function)
        address = get_address_of_so_function_in_zygote(function, so_file)
        STATIC_INFO_LOOKUP_TABLE[address] =\
            {'name': name, 'is_kprobe': False, 'is_special': False}  # special means Android API call in case of uprobe

    for oat_func in config_dict['uprobes-oat']:
        oat_path = oat_func['oat_file']
        function = oat_func['function']
        name, arguments, _ = get_function_name_arguments_and_return_value_from_declaration(function)
        name = name + '(' + ','.join(arguments) + ')'
        address, returns = get_entry_and_returns_of_oat_function_in_zygote(function, oat_path)
        if address:
            if address in STATIC_INFO_LOOKUP_TABLE:
                oat_func['disabled'] = True
                LOGGER.info(f"WARNING: Address of {name} (0x{address:x}) is already in use for method {STATIC_INFO_LOOKUP_TABLE[address]['name']}")
            else:
                STATIC_INFO_LOOKUP_TABLE[address] =\
                    {'name': name, 'is_kprobe': False, 'is_special': True, 'returns': [hex(ret) for ret in returns]}
                # special = Android API call in case of uprobe


def print_lookup_table(table):
    LOGGER.info("Lookup Table:")
    for addr, e in table.items():
        LOGGER.info(f"0x{addr:x}: {e}")


def attach_kprobe_and_kretprobe(b, kernel_function_name, entry_trace_function, return_trace_function):
    global NUM_TOTAL_PROBES
    try:
        b.attach_kprobe(event=kernel_function_name, fn_name=entry_trace_function)
        NUM_TOTAL_PROBES += 1
        if config.DEBUG:
            LOGGER.info(f'DEBUG: Attached kprobe to {kernel_function_name} triggering {entry_trace_function}')
        b.attach_kretprobe(event=kernel_function_name, fn_name=return_trace_function)
        NUM_TOTAL_PROBES += 1
        if config.DEBUG:
            LOGGER.info(f'DEBUG: Attached kretprobe to {kernel_function_name} triggering {return_trace_function}')
    except Exception as ex:
        LOGGER.info(f"EXCEPTION while attaching {kernel_function_name}: {ex} (Total Probes: {NUM_TOTAL_PROBES})")


def attach_probes(config_dict, b):
    global NUM_TOTAL_PROBES
    # attach kprobes to syscalls
    for syscall_entry in config_dict['kprobes-syscalls']:
        syscall_declaration = syscall_entry['function']
        if syscall_entry['override']:
            entry_trace_function = config.ENTRY_TRACE_FUNCTION_WITH_OVERRIDE
            return_trace_function = config.RETURN_TRACE_FUNCTION_WITH_OVERRIDE
        else:
            entry_trace_function = config.ENTRY_TRACE_FUNCTION_WITHOUT_OVERRIDE
            return_trace_function = config.RETURN_TRACE_FUNCTION_WITHOUT_OVERRIDE
        kernel_function_name, _, _ = get_function_name_arguments_and_return_value_from_declaration(syscall_declaration,
                                                                                                   True)
        if kernel_function_name not in KPROBES_NOT_FOUND:
            attach_kprobe_and_kretprobe(b, kernel_function_name, entry_trace_function, return_trace_function)

    # attach kprobes to non-syscalls
    for function_entry in config_dict['kprobes-non-syscalls']:
        function_declaration = function_entry['function']
        if function_entry['override']:
            entry_trace_function = config.ENTRY_TRACE_FUNCTION_WITH_OVERRIDE
            return_trace_function = config.RETURN_TRACE_FUNCTION_WITH_OVERRIDE
        else:
            entry_trace_function = config.ENTRY_TRACE_FUNCTION_WITHOUT_OVERRIDE
            return_trace_function = config.RETURN_TRACE_FUNCTION_WITHOUT_OVERRIDE
        kernel_function_name, _, _ = get_function_name_arguments_and_return_value_from_declaration(function_declaration,
                                                                                                   False)
        if kernel_function_name not in KPROBES_NOT_FOUND:
            attach_kprobe_and_kretprobe(b, kernel_function_name, entry_trace_function, return_trace_function)

    # attach uprobes to native library functions
    for native_function_entry in config_dict['uprobes-so']:
        if native_function_entry['override']:
            entry_trace_function = config.ENTRY_TRACE_FUNCTION_WITH_OVERRIDE
            return_trace_function = config.RETURN_TRACE_FUNCTION_WITH_OVERRIDE
        else:
            entry_trace_function = config.ENTRY_TRACE_FUNCTION_WITHOUT_OVERRIDE
            return_trace_function = config.RETURN_TRACE_FUNCTION_WITHOUT_OVERRIDE
        try:
            function = native_function_entry['function']
            b.attach_uprobe(name=native_function_entry['so_file'],
                            sym=function,
                            fn_name=entry_trace_function)
            NUM_TOTAL_PROBES += 1
            if config.DEBUG:
                LOGGER.info(f'DEBUG: Attached uprobe to {function} triggering {entry_trace_function}')
            b.attach_uretprobe(name=native_function_entry['so_file'],
                               sym=function,
                               fn_name=return_trace_function)
            NUM_TOTAL_PROBES += 1
            if config.DEBUG:
                LOGGER.info(f'DEBUG: Attached uretprobe to {function} triggering {return_trace_function}')
        except Exception as ex:
            LOGGER.info(f"EXCEPTION while attaching {function}: {ex} (Total Probes: {NUM_TOTAL_PROBES})")

    # attach uprobes to android api functions
    for aapi_function_entry in config_dict['uprobes-oat']:
        if 'disabled' in aapi_function_entry:
            continue
        if aapi_function_entry['override']:
            entry_trace_function = config.ENTRY_TRACE_FUNCTION_WITH_OVERRIDE
            return_trace_function = config.RETURN_TRACE_FUNCTION_WITH_OVERRIDE
        else:
            entry_trace_function = config.ENTRY_TRACE_FUNCTION_WITHOUT_OVERRIDE
            return_trace_function = config.RETURN_TRACE_FUNCTION_WITHOUT_OVERRIDE
        function = aapi_function_entry['function']
        offset, returns = get_offset_of_aapi_function_entry_and_returns_in_oat_file(function, aapi_function_entry['oat_file'])
        if offset:
            try:
                b.attach_uprobe(name=aapi_function_entry['oat_file'],
                                addr=offset + 0x1000,
                                fn_name=entry_trace_function)
                NUM_TOTAL_PROBES += 1
                if config.DEBUG:
                    LOGGER.info(f'DEBUG: Attached uprobe to {function} (oat-file offset: 0x{offset + 0x1000:x}) triggering {entry_trace_function}')
                if config.ENABLE_AAPI_RETURN_TRACING:
                    if returns:
                        for return_offset in returns:
                            b.attach_uprobe(name=aapi_function_entry['oat_file'],
                                            addr=return_offset + 0x1000,
                                            fn_name=return_trace_function)
                            NUM_TOTAL_PROBES += 1
                        if config.DEBUG:
                            LOGGER.info(f'DEBUG: Attached return-uprobe to {function} (oat-file offset: 0x{return_offset + 0x1000:x})'
                                        f' triggering {return_trace_function}')
            except Exception as ex:
                LOGGER.info(f"EXCEPTION: Exception while attaching {function}: {ex} (Total Probes: {NUM_TOTAL_PROBES})")


def generic_event_handler(static_info, e):
    # ret = unsigned_to_signed64(e.ret)
    debug = unsigned_to_signed64(e.debug)
    payload_string = bytearray(e.payload_bytes).split(b'\x00')[0]
    print_event(static_info, e, b"payload: '%s' 0x%-10x 0x%-10x 0x%-10x (debug: %d)" %
                (payload_string, e.arg1, e.arg2, e.arg3, debug))


def print_event(static_info, e, event_str):
    if e.type == EventType.INCOMPLETE_EVENT:
        event_str = b"(stack full) " + event_str
    result = get_generic_print_part(static_info, e) + event_str
    LOGGER.info(convert_byte_array(result))


def convert_byte_array(byte_array):
    # Convert byte array to string
    my_str = byte_array.decode('ascii', 'backslashreplace')

    # Replace non-printable characters with hex representation
    hex_string = ""
    for char in my_str:
        if ord(char) < 32 or ord(char) > 126:
            hex_string += "\\x{:02x}".format(ord(char))
        else:
            hex_string += char

    return hex_string


def get_generic_print_part(static_info=None, event=False):
    format_str = b"%-6d %-20s %-6d %-6d %-6d %-16s 0x%-17x %-10d | "
    if event:
        name = static_info['name']
        name = name.split('(')[0].encode()
        name = name if len(name) <= 20 else name[-20:]
        return format_str % (event.level, name, event.tgid, event.pid, event.ppid, event.comm,
                             event.context_ip, unsigned_to_signed64(event.ret_value))
    else:
        format_str = "%-6s %-20s %-6s %-6s %-6s %-16s %-19s %-10s | "
        return format_str % ("Level", "Event", "PID", "TID", "PPID", "COMM",
                             "ENTRY", "RET")


def generate_reduced_result_table(table):
    stats = {}
    for k, v in table.items():
        if 'counter' in v:
            stats[k] = v
    result_table = dict(sorted(stats.items(), key=lambda item: item[1]['counter']))
    result_table_reduced = dict()
    for k, v in result_table.items():
        del v["is_kprobe"]
        del v["is_special"]
        if "event_handler" in v:
            del v["event_handler"]
        if "returns" in v:
            del v["returns"]
        result_table_reduced[k] = v
    return result_table_reduced


def save_to_file(result_table_reduced, random_id, app_package_name):
    ts = (datetime.now() + timedelta(hours=2)).strftime("%Y-%m-%d-%H-%M")
    result_table_file = f"{config.OUTPUT_FOLDER}/{random_id}-{app_package_name}-{ts}.json"
    with open(result_table_file, 'w') as f:
        f.write(json.dumps(result_table_reduced, indent=4))


def unsigned_to_signed64(x):
    if x >= 2 ** (64 - 1):
        x -= 2 ** 64
    return x


def check_or_prepare_inverted_lookup_table():
    global INVERTED_LOOKUP_TABLE
    if not INVERTED_LOOKUP_TABLE:
        INVERTED_LOOKUP_TABLE = {}
        for address, e in STATIC_INFO_LOOKUP_TABLE.items():
            INVERTED_LOOKUP_TABLE[e['name']] = address


def add_event_handler(probe_name, event_handler):
    global INVERTED_LOOKUP_TABLE
    check_or_prepare_inverted_lookup_table()
    if probe_name in INVERTED_LOOKUP_TABLE:
        STATIC_INFO_LOOKUP_TABLE[INVERTED_LOOKUP_TABLE[probe_name]]['event_handler'] = event_handler
    else:
        LOGGER.info(f"WARNING: Error when adding an event handler. No probe with name '{probe_name}' in lookup table.")


def add_tracing_segment(probe_name, segment, segments):
    global INVERTED_LOOKUP_TABLE
    check_or_prepare_inverted_lookup_table()
    if probe_name in INVERTED_LOOKUP_TABLE or probe_name == "*":
        segments.append(segment)
        if config.DEBUG:
            LOGGER.info(f"INFO: Added tracing segment for {probe_name}:\n{segment}")
    else:
        LOGGER.info(f"WARNING: Error when adding a tracing segment. No probe with name '{probe_name}' in lookup table.")


def apply_entry_tracing_segments(segments_without_override, segments_with_override, bpf_program):
    entry_tracing_segments_block = ""
    for segment in segments_without_override:
        entry_tracing_segments_block += segment + '\n'
    bpf_program = bpf_program.replace('    // ENTRY_TRACING_BLOCK_WITHOUT_OVERRIDE\n', entry_tracing_segments_block)

    entry_tracing_segments_block_with_override = ""
    for segment in segments_with_override:
        entry_tracing_segments_block_with_override += segment + '\n'
    bpf_program = bpf_program.replace('    // ENTRY_TRACING_BLOCK_WITH_OVERRIDE\n',
                                      entry_tracing_segments_block_with_override)
    return bpf_program


def apply_return_tracing_segments(segments_without_override, segments_with_override, bpf_program):
    return_tracing_segments_block_without_override = ""
    for segment in segments_without_override:
        return_tracing_segments_block_without_override += segment + '\n'
    bpf_program = bpf_program.replace('    // RETURN_TRACING_BLOCK_WITHOUT_OVERRIDE\n',
                                      return_tracing_segments_block_without_override)

    return_tracing_segments_block_with_override = ""
    for segment in segments_with_override:
        return_tracing_segments_block_with_override += segment + '\n'
    bpf_program = bpf_program.replace('    // RETURN_TRACING_BLOCK_WITH_OVERRIDE\n',
                                      return_tracing_segments_block_with_override)
    return bpf_program


def apply_event_stacks_block(bpf_program):
    num_stacks = config.NUMBER_STACK_LEVELS
    stacks_code = "BPF_HASH(event_map_current_level, u32, u64, 10240); // event_map_current_level[pid] = i means, that unlimited stack would be filled until and including index i\n"
    for i in range(num_stacks):
        stacks_code += f"BPF_HASH(event_map_level{i}, u32, struct event_t, 10240);\n"
    stacks_code += f"BPF_ARRAY_OF_MAPS(event_stacks, \"event_map_level0\", {num_stacks});\n"
    bpf_program = bpf_program.replace('// EVENT_STACKS_BLOCK\n', stacks_code)
    return bpf_program


def prepare_tracing_segments(segments_file, entry_tracing_segments, return_tracing_segments):
    tracing_segments = parse_tracing_segments(segments_file)
    for entry in tracing_segments['ENTRY']:
        label, segment = entry['label'], entry['segment']
        add_tracing_segment(label, segment, entry_tracing_segments)
    for entry in tracing_segments['RETURN']:
        label, segment = entry['label'], entry['segment']
        add_tracing_segment(label, segment, return_tracing_segments)


def generate_tracing_functions_with_override(without_override_block):
    with_override_block = without_override_block.replace("syscall__generic_entry_trace_function_without_override",
                                                         "syscall__generic_entry_trace_function_with_override")
    with_override_block = with_override_block.replace("generic_return_trace_function_without_override",
                                                      "generic_return_trace_function_with_override")
    with_override_block = with_override_block.replace("// ENTRY_TRACING_BLOCK_WITHOUT_OVERRIDE",
                                                      "// ENTRY_TRACING_BLOCK_WITH_OVERRIDE")
    with_override_block = with_override_block.replace("// RETURN_TRACING_BLOCK_WITHOUT_OVERRIDE",
                                                      "// RETURN_TRACING_BLOCK_WITH_OVERRIDE")
    return with_override_block


def timeout_handler():
    LOGGER.info("")
    LOGGER.info("Timeout")
    os.kill(os.getpid(), signal.SIGINT)


def start_timer(timeout):
    global TIMER
    if timeout >= 0:
        TIMER = threading.Timer(timeout, timeout_handler)
        TIMER.start()


def read_config_file():
    global CONFIG_DICT
    with open(config.CONFIG_FILE, 'r') as file:
        try:
            CONFIG_DICT = json.loads(file.read())
        except JSONDecodeError as e:
            print(f"ERROR: Please check json syntax of config file: {e}")
            exit()


class LoggerWriter:
    def __init__(self, level):
        self.level = level

    def write(self, message):
        if message != '\n':
            self.level(message)

    def flush(self):
        self.level(sys.stderr)
