#include <linux/sched.h>
#include <net/sock.h>
#include <linux/mm.h>

#define DATA_LENGTH 80
#define MAX_ARGUMENTS 5
// DISABLE_ANDROID_API_RETURN_TRACING_BLOCK
// ENABLE_CHECK_ANDROID_API_RETURN_ADDRESS_BLOCK

// Macros for function addresses
// FUNCTION_ADDRESSES_BLOCK

enum event_type {
    ENTRY_EVENT,
    RETURN_EVENT,
    FINAL_EVENT,
    INCOMPLETE_EVENT,
    ERROR_EVENT
};

struct event_t {
    u32 pid;                            // process ID (kernel) = TID (user space)
    u32 tgid;                           // thread group ID (kernel) = PID (user space)
    u32 ppid;                           // parent PID
    char comm[TASK_COMM_LEN];           // process name
    u64 context_ip;                     // instruction pointer of context at function entry
    u64 context_sp;                     // stack pointer of context at function entry
    u64 arg1;                           // generic arg1
    u64 arg2;                           // generic arg2
    u64 arg3;                           // generic arg3
    u64 arg4;                           // generic arg4
    u64 arg5;                           // generic arg5
    char arg1_data[DATA_LENGTH / 5];    // generic arg1 indirect data
    char arg2_data[DATA_LENGTH / 5];    // generic arg2 indirect data
    char arg3_data[DATA_LENGTH / 5];    // generic arg3 indirect data
    char arg4_data[DATA_LENGTH / 5];    // generic arg4 indirect data
    char arg5_data[DATA_LENGTH / 5];    // generic arg5 indirect data
    u64 ret_value;                      // return value
    enum event_type type;               // event type
    u64 payload_bytes[DATA_LENGTH / 8]; // generic bytes payload
    u64 debug;                          // debug data
    u64 level;                          // stack level
    u64 return_context_ip;              // instruction pointer of context at function return
};

struct probe_type_t {
    u32 is_kprobe;
    u32 is_special;                     // is_special + kprobe -> syscall, is_special + uprobe -> Android API function
    u64 expected_return_ips[5];         // used for checking the instruction pointer in return tracing function
};

BPF_PERF_OUTPUT(events);
BPF_HASH(type_map, u64, struct probe_type_t, 102400);

// EVENT_STACKS_BLOCK

static void write_msg_to_event(char msg[], struct event_t *event_ptr, int size) {
    if (size > DATA_LENGTH) {
        size = DATA_LENGTH;
    }
    for (int i = 0; i < size; i++) {
        char* dst = (char*) event_ptr->payload_bytes;
        dst[i] = msg[i];
    }
}

// tracing functions WITHOUT override
int syscall__generic_entry_trace_function_without_override(struct pt_regs *ctx, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
    u64 parm1 = PT_REGS_PARM1(ctx);
    u64 parm2 = PT_REGS_PARM2(ctx);
    u64 parm3 = PT_REGS_PARM3(ctx);
    u64 parm4 = PT_REGS_PARM4(ctx);
    u64 parm5 = PT_REGS_PARM5(ctx);

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    // UID_FILTER_BLOCK

    // type lookup:
    // * syscall (kprobe, special)
    // * (non-syscall) kernel function (kprobe, non-special)
    // * native library function (uprobe, non-special)
    // * Android API function (uprobe, special)
    u32 is_kprobe = 0;
    u32 is_special = 0;
    u64 context_ip = (u64) ctx->ip;
    struct probe_type_t *probe_type_ptr = type_map.lookup(&context_ip);
    if (probe_type_ptr == 0) {
        // didn't find a type map entry for that address -> error
        struct event_t error_event = {};
        error_event.type = ERROR_EVENT;
        error_event.context_ip = context_ip;
        char msg[] = "didn't find a type map entry for that address";
        write_msg_to_event(msg, &error_event, sizeof(msg));
        events.perf_submit(ctx, &error_event, sizeof(error_event));
        return 0;
    }

    is_kprobe = probe_type_ptr->is_kprobe;
    is_special = probe_type_ptr->is_special;

    // construct event template
    struct event_t event_template = {};
    u64 tgid_pid = bpf_get_current_pid_tgid();
    event_template.tgid = tgid_pid >> 32;
    u32 pid = tgid_pid; // 64 bit to 32 bit
    event_template.pid = pid;
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    event_template.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&event_template.comm, sizeof(event_template.comm));
    event_template.context_ip = ctx->ip;
    event_template.context_sp = ctx->sp;

    if (is_kprobe && is_special) {  // syscall (kprobe, special)
        event_template.arg1 = arg1;
        event_template.arg2 = arg2;
        event_template.arg3 = arg3;
        event_template.arg4 = arg4;
        event_template.arg5 = arg5;
    } else {                        // all other cases
        event_template.arg1 = parm1;
        event_template.arg2 = parm2;
        event_template.arg3 = parm3;
        event_template.arg4 = parm4;
        event_template.arg5 = parm5;
    }

    struct event_t* event_ptr = &event_template;
    event_ptr->type = ENTRY_EVENT;

    // ENTRY_TRACING_BLOCK_WITHOUT_OVERRIDE

    #if defined(DISABLE_ANDROID_API_RETURN_TRACING)
    if (!is_kprobe && is_special) {  // Android API function (uprobe, special)
        // return tracing is disabled; event template gets submitted as incomplete event and is not stored on the stack
        event_ptr->type = INCOMPLETE_EVENT;
        events.perf_submit(ctx, event_ptr, sizeof(*event_ptr));
        return 0; // event and is not stored on the stack
    }
    #endif

    // look up which stack level should be used
    u64* current_level = event_map_current_level.lookup(&pid);
    u64 new_level;
    if (!current_level) {
        // no level present
        new_level = 0;
    } else {
        new_level = *current_level + 1;
    }
    event_map_current_level.update(&pid, &new_level);
    event_ptr->level = new_level;

    // get the corresponding level map
    void *inner_map = event_stacks.lookup((int*) &new_level);
    if (!inner_map) {
        // stack is full; event template gets submitted as incomplete event and is not stored on the stack
        event_ptr->type = INCOMPLETE_EVENT;
        event_ptr->debug = new_level;
        events.perf_submit(ctx, event_ptr, sizeof(*event_ptr));
        return 0; // event and is not stored on the stack
    }

    // insert event template into event stack of next free level
    long err = bpf_map_update_elem(inner_map, &pid, event_ptr, BPF_NOEXIST);
    if (err) {
        // failed to update event stack -> error
        event_ptr->type = ERROR_EVENT;
        event_ptr->debug = err;
        char msg[] = "failed to update event stack\0";
        write_msg_to_event(msg, event_ptr, sizeof(msg));
        events.perf_submit(ctx, event_ptr, sizeof(*event_ptr));
    }

    return 0;
}

int generic_return_trace_function_without_override(struct pt_regs *ctx)
{
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    // UID_FILTER_BLOCK

    struct event_t error_event = {};
    error_event.type = ERROR_EVENT;
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 pid = tgid_pid; // 64 bit to 32 bit
    // lookup the current level
    u64* current_level = event_map_current_level.lookup(&pid);
    if (!current_level) {
        // lookup of stack level failed for given pid -> error
        error_event.return_context_ip = ctx->ip;
        char msg[] = "lookup of stack level failed for given pid";
        write_msg_to_event(msg, &error_event, sizeof(msg));
        events.perf_submit(ctx, &error_event, sizeof(error_event));
        return 0;
    }

    // get the level map for retrieved level
    void *inner_map = event_stacks.lookup((int*) current_level);
    if (!inner_map) {
        u64 new_level = *current_level - 1;
        event_map_current_level.update(&pid, &new_level);
        return 0; // because the stack is not large enough and there is no event for that level to retrieve
    }

    // retrieve event template from retrieved level map
    struct event_t *event_ptr = bpf_map_lookup_elem(inner_map, &pid);
    if (!event_ptr) {
        // stack error
        error_event.debug = pid; //*current_level;
        char msg[] = "stack error\0";
        write_msg_to_event(msg, &error_event, sizeof(msg));
        events.perf_submit(ctx, &error_event, sizeof(error_event));
        return 0;
    }

    // an event was retrieved successfully

    #if defined(CHECK_ANDROID_API_RETURN_ADDRESSES)
    //check if return context ip matches one of the expected values in case of Android API call
    struct probe_type_t *probe_type_ptr = type_map.lookup(&event_ptr->context_ip);
    if (probe_type_ptr == 0) {
        // didn't find a type map entry for that address -> error
        event_ptr->type = ERROR_EVENT;
        char msg[] = "didn't find a type map entry for that address";
        write_msg_to_event(msg, event_ptr, sizeof(msg));
        events.perf_submit(ctx, event_ptr, sizeof(*event_ptr));
        return 0;
    }
    if (!probe_type_ptr->is_kprobe && probe_type_ptr->is_special) { // Android API function
        bool found = false;
        for (int i = 0; i < 5; i++) {
            if (ctx->ip == probe_type_ptr->expected_return_ips[i]) {
                found = true;
                break;
            }
        }
        if (!found) {
            // return context ip doesn't match one of the expected values -> error
            event_ptr->type = ERROR_EVENT;
            char msg[] = "return context ip doesn't match one of the expected values";
            write_msg_to_event(msg, event_ptr, sizeof(msg));
            events.perf_submit(ctx, event_ptr, sizeof(*event_ptr));
        }
    }
    #endif

    event_ptr->return_context_ip = ctx->ip;
    event_ptr->ret_value = PT_REGS_RC(ctx);
    event_ptr->type = RETURN_EVENT;

    // interpret arguments of function as pointer to data, read the data, write it into the event
    bpf_probe_read_user(&event_ptr->arg1_data, sizeof(event_ptr->arg1_data), (void *) event_ptr->arg1);
    bpf_probe_read_user(&event_ptr->arg2_data, sizeof(event_ptr->arg2_data), (void *) event_ptr->arg2);
    bpf_probe_read_user(&event_ptr->arg3_data, sizeof(event_ptr->arg3_data), (void *) event_ptr->arg3);
    bpf_probe_read_user(&event_ptr->arg4_data, sizeof(event_ptr->arg4_data), (void *) event_ptr->arg4);
    bpf_probe_read_user(&event_ptr->arg5_data, sizeof(event_ptr->arg5_data), (void *) event_ptr->arg5);

    // RETURN_TRACING_BLOCK_WITHOUT_OVERRIDE

    // complete and submit final event
    event_ptr->ret_value = PT_REGS_RC(ctx);
    event_ptr->type = FINAL_EVENT;
    events.perf_submit(ctx, event_ptr, sizeof(*event_ptr));  // submit final event

    // update current level map
    if (*current_level == 0) {
         // stack is empty now
         event_map_current_level.delete(&pid);
    } else {
        u64 new_level = *current_level - 1;
        event_map_current_level.update(&pid, &new_level);
    }

    // delete event template from level map
    long err = bpf_map_delete_elem(inner_map, &pid);
    if (err) {
        // stack error
        event_ptr->type = ERROR_EVENT;
        event_ptr->debug = err;
        event_ptr->return_context_ip = ctx->ip;
        char msg[] = "stack error";
        write_msg_to_event(msg, event_ptr, sizeof(msg));
        events.perf_submit(ctx, event_ptr, sizeof(*event_ptr));
    }

    return 0;
}
