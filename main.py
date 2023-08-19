#!/usr/bin/env python3

import json
import sys
import os
from json import JSONDecodeError
from bcc import BPF
from event_handler import execve_syscall_event_handler, openat_syscall_event_handler, getaddrinfofornet_event_handler, \
    connect_syscall_event_handler, tcp_v4_connect_event_handler, base64_decode_event_handler, \
    getdents64_event_handler, EventType, file_getpath_event_handler
from helper import apply_uid_filter_code_block, parse_arguments, fill_lookup_table, print_lookup_table, \
    attach_probes, fill_type_map, generic_event_handler, apply_function_addresses_block, add_event_handler, \
    apply_entry_tracing_segments, apply_return_tracing_segments, unsigned_to_signed64, get_generic_print_part, \
    apply_disable_android_api_return_tracing_block, generate_random_id, start_timer, read_config_file, set_up_logging, \
    apply_enable_check_android_api_return_addresses_block, setup_event_stacks, apply_event_stacks_block, \
    prepare_tracing_segments, generate_tracing_functions_with_override, generate_reduced_result_table, save_to_file
import helper
import config


def main():
    # read config file
    read_config_file()

    # parse cli arguments
    app_package_name, app_uid = parse_arguments()

    # set up logging
    random_id = generate_random_id(5)
    set_up_logging(app_package_name, random_id)

    helper.LOGGER.info(f"App: {app_package_name}")
    helper.LOGGER.info(f"UID/GID: {app_uid}")

    # prepare and print lookup table
    fill_lookup_table(helper.CONFIG_DICT)
    helper.LOGGER.info("")
    print_lookup_table(helper.STATIC_INFO_LOOKUP_TABLE)
    helper.LOGGER.info("")

    # prepare tracing segments...
    # ... without override
    entry_tracing_segments_without_override = []
    return_tracing_segments_without_override = []
    prepare_tracing_segments(config.TRACING_SEGMENTS_WITHOUT_OVERRIDE_FILE,
                             entry_tracing_segments_without_override,
                             return_tracing_segments_without_override)
    # ... with override
    entry_tracing_segments_with_override = []
    return_tracing_segments_with_override = []
    prepare_tracing_segments(config.TRACING_SEGMENTS_WITH_OVERRIDE_FILE,
                             entry_tracing_segments_with_override,
                             return_tracing_segments_with_override)

    # add event handlers
    add_event_handler('__x64_sys_getdents64', getdents64_event_handler)
    add_event_handler('__x64_sys_openat', openat_syscall_event_handler)
    add_event_handler('__x64_sys_execve', execve_syscall_event_handler)
    add_event_handler('android_getaddrinfofornet', getaddrinfofornet_event_handler)
    add_event_handler('__x64_sys_connect', connect_syscall_event_handler)
    add_event_handler('tcp_v4_connect', tcp_v4_connect_event_handler)
    add_event_handler('android.util.Base64.decode(java.lang.String,int)', base64_decode_event_handler)
    add_event_handler('java.io.File.getPath()', file_getpath_event_handler)

    # read BPF program template
    bpf_program = open(config.BPF_PROGRAM_TEMPLATE_FILE, 'r').read()

    # generate tracing functions with override
    without_override_block = bpf_program.split("// tracing functions WITHOUT override")[1]
    bpf_program += "\n// tracing functions WITH override"
    bpf_program += generate_tracing_functions_with_override(without_override_block)

    # prepare BPF program
    if not config.ENABLE_AAPI_RETURN_TRACING:
        bpf_program = apply_disable_android_api_return_tracing_block(bpf_program)
    if config.ENABLE_CHECKING_AAPI_RETURN_ADDRESSES:
        bpf_program = apply_enable_check_android_api_return_addresses_block(bpf_program)
    bpf_program = apply_function_addresses_block(bpf_program)
    bpf_program = apply_uid_filter_code_block(app_uid, bpf_program)
    bpf_program = apply_event_stacks_block(bpf_program)
    bpf_program = apply_entry_tracing_segments(entry_tracing_segments_without_override,
                                               entry_tracing_segments_with_override, bpf_program)
    bpf_program = apply_return_tracing_segments(return_tracing_segments_without_override,
                                                return_tracing_segments_with_override, bpf_program)

    # save resulting BPF program for debugging
    with open('bpf-last-program.tmp', 'w') as file_:
        file_.write(bpf_program)

    # initialize BPF
    b = BPF(text=bpf_program, debug=0)  # debug=DEBUG_PREPROCESSOR, debug=DEBUG_SOURCE

    # set up event stack
    setup_event_stacks(b)

    # fill type map for type lookup in BPF program
    fill_type_map(b)

    # attach probes
    attach_probes(helper.CONFIG_DICT, b)

    # call event handler for single event
    def call_event_handler(static_info, event):
        if 'counter' not in static_info:
            static_info['counter'] = 0
        static_info['counter'] += 1
        if 'event_handler' in static_info:
            # event with event handler
            static_info['event_handler'](static_info, event)
        else:
            # event without custom event handler, so call generic one
            generic_event_handler(static_info, event)

    # process event
    def process_event_from_kernel(cpu, data, size):
        event = b["events"].event(data)
        # check if it is an error event
        if event.type == EventType.ERROR_EVENT:
            payload_string = bytearray(event.payload_bytes).split(b'\x00')[0].decode(errors='replace')
            helper.LOGGER.info(f"ERROR: Error Event with message \"{payload_string}\" "
                               f"and debug value: {unsigned_to_signed64(event.debug)}")
            helper.ERROR_EVENTS_OCCURRED = True
            return
        # get static info by using the IP as key for the lookup table
        static_info = helper.STATIC_INFO_LOOKUP_TABLE.get(event.context_ip, None)
        if static_info:
            call_event_handler(static_info, event)
        else:
            helper.LOGGER.info("INFO: Event with IP %x is not in lookup table." % event.context_ip)

    helper.LOGGER.info("")
    generic_part = get_generic_print_part()
    helper.LOGGER.info(generic_part + "event specific data")

    b["events"].open_perf_buffer(process_event_from_kernel)

    # main loop
    try:
        start_timer(config.TIMEOUT)
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        if helper.TIMER:
            helper.TIMER.cancel()
        lookup_table_reduced = generate_reduced_result_table(helper.STATIC_INFO_LOOKUP_TABLE)
        helper.LOGGER.info("")
        print_lookup_table(lookup_table_reduced)
        save_to_file(lookup_table_reduced, random_id, app_package_name)
        helper.LOGGER.info("")
        helper.LOGGER.info(f"Total probes: {helper.NUM_TOTAL_PROBES}")
        if helper.ERROR_EVENTS_OCCURRED:
            helper.LOGGER.info("")
            helper.LOGGER.info("")
            helper.LOGGER.info("!!! ERROR EVENTS OCCURRED !!!")
            helper.LOGGER.info("")
        exit()


if __name__ == '__main__':
    main()
