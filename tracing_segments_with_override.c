int this_name_has_no_purpose()
{
    // RETURN TRACING SEGMENT: __x64_sys_openat
    // return tracing segment for openat
    if (event_ptr->context_ip == ADR___X64_SYS_OPENAT) {
        bpf_probe_read_user_str(&event_ptr->payload_bytes, sizeof(event_ptr->payload_bytes), (void *) event_ptr->arg2);
        if (((char*) event_ptr->payload_bytes)[11] == '0') {
            bpf_override_return(ctx, -ENOENT);
        }
    }

    // RETURN TRACING SEGMENT: __x64_sys_faccessat
    // return tracing segment for faccessat
    if (event_ptr->context_ip == ADR___X64_SYS_FACCESSAT) {
        bpf_override_return(ctx, -ENOENT);
    }
}