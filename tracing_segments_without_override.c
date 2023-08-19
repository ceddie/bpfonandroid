int this_name_has_no_purpose()
{
    // ENTRY TRACING SEGMENT: __x64_sys_openat
    // entry tracing segment for openat
    if (event_ptr->context_ip == ADR___X64_SYS_OPENAT) {
        bpf_probe_read_user_str(&event_ptr->payload_bytes, sizeof(event_ptr->payload_bytes), (void *) event_ptr->arg2);
    }

    // RETURN TRACING SEGMENT: __x64_sys_getdents64
    // return tracing segment for getdents64
    if (event_ptr->context_ip == ADR___X64_SYS_GETDENTS64) { // getdents64(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
        struct linux_dirent64 {
                u64             d_ino;
                s64             d_off;
                unsigned short  d_reclen;
                unsigned char   d_type;
                char            d_name[];
        };

        const struct linux_dirent64 *dirp = (struct linux_dirent64 *) event_ptr->arg2;

        if (dirp == NULL) {
            return 0;
        }

        int nread = event_ptr->ret_value;
        if (nread == -1) {
            return 0;
        }

        if (nread == 0) {
            return 0;
        }

        bpf_probe_read_user(&event_ptr->payload_bytes, sizeof(event_ptr->payload_bytes), (void*) dirp);

        struct linux_dirent64 *d;
        u64 bpos = 0;
        for (int i = 0; i < 3; i++) {
            if (bpos >= nread) {
                break;
            }
            d = (struct linux_dirent64 *) ((void*) dirp + bpos);

            unsigned short current_d_reclen;
            bpf_probe_read_user(&current_d_reclen, sizeof(current_d_reclen), (void*) &(d->d_reclen));

            if (i==2) {
                char replace[] = "BLAA";
                //bpf_probe_write_user((char *) d->d_name, replace, sizeof(replace) - 1);
            }

            u64 d_name_len = current_d_reclen - 2 - (offsetof(struct linux_dirent64, d_name));
            char current_d_name[30];
            bpf_probe_read_user_str(&current_d_name, sizeof(current_d_name), (void*) d->d_name);
            bpf_probe_read_kernel(&event_ptr->payload_bytes, sizeof(event_ptr->payload_bytes), (void *) current_d_name);
            events.perf_submit(ctx, event_ptr, sizeof(struct event_t));

            bpos += current_d_reclen;
        }
    }

    // ENTRY TRACING SEGMENT: __x64_sys_execve
    // entry tracing segment for execve
    if (event_ptr->context_ip == ADR___X64_SYS_EXECVE) { // execve(const char *filename, char *const argv[], char *const envp[]);
        bpf_probe_read_user_str(&event_ptr->payload_bytes, sizeof(event_ptr->payload_bytes), (void *) event_ptr->arg1);
        events.perf_submit(ctx, event_ptr, sizeof(struct event_t)); // submit first entry event

        for (int i = 1; i < MAX_ARGUMENTS; i++) {
            const char *const *argv = (const char *const *) event_ptr->arg2;
            const char *const *arg_ptr_ptr =  &argv[i];
            const char *arg_ptr = NULL;
            bpf_probe_read_user_str(&arg_ptr, sizeof(arg_ptr), (void*) arg_ptr_ptr);
            if (arg_ptr) {
                bpf_probe_read_user_str(&event_ptr->payload_bytes, sizeof(event_ptr->payload_bytes), (void *)(arg_ptr));
                events.perf_submit(ctx, event_ptr, sizeof(struct event_t)); // submit more entry events
            } else {
                break;
            }
        }
    }

    // RETURN TRACING SEGMENT: __x64_sys_connect
    // return tracing segment for connect
    if (event_ptr->context_ip == ADR___X64_SYS_CONNECT) { // connect(int socket, const struct sockaddr *address, socklen_t address_len)
        struct sockaddr *sadr = (struct sockaddr*) event_ptr->arg2;
        // struct sockaddr {
        //  unsigned short   sa_family;
        //  char             sa_data[14];
        // };
        bpf_probe_read_user_str(&event_ptr->payload_bytes, sizeof(event_ptr->payload_bytes), (void *)&sadr->sa_data);
    }

    // RETURN TRACING SEGMENT: tcp_v4_connect
    // return tracing segment for tcp_v4_connect
    if (event_ptr->context_ip == ADR_TCP_V4_CONNECT) { // tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
        struct sock *skp = (struct sock*) event_ptr->arg1;

        struct tcp_v4_connect_data {
            u32 saddr;
            u32 daddr;
            u16 lport;
            u16 dport;
        } data;

        bpf_probe_read_kernel(&data.lport, sizeof(data.lport), (void *)&skp->__sk_common.skc_num);
        bpf_probe_read_kernel(&data.dport, sizeof(data.dport), (void *)&skp->__sk_common.skc_dport);
        bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), (void *)&skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), (void *)&skp->__sk_common.skc_daddr);

        data.dport = ntohs(data.dport);

        bpf_probe_read_kernel(&event_ptr->payload_bytes, sizeof(struct tcp_v4_connect_data), (void *) &data);
    }


    // ENTRY TRACING SEGMENT: *
    #ifndef ADR_JAVA__LANG__CLASSLOADER__LOADCLASS_JAVA__LANG__STRING_
    #define ADR_JAVA__LANG__CLASSLOADER__LOADCLASS_JAVA__LANG__STRING_ 0
    #endif
    #ifndef ADR_ANDROID__APP__CONTEXTIMPL__CHECKPERMISSION_JAVA__LANG__STRING_INT_INT_
    #define ADR_ANDROID__APP__CONTEXTIMPL__CHECKPERMISSION_JAVA__LANG__STRING_INT_INT_ 0
    #endif
    #ifndef ADR_ANDROID__APP__CONTEXTIMPL__CHECKPERMISSION_JAVA__LANG__STRING_INT_INT_ANDROID__OS__IBINDER_
    #define ADR_ANDROID__APP__CONTEXTIMPL__CHECKPERMISSION_JAVA__LANG__STRING_INT_INT_ANDROID__OS__IBINDER_ 0
    #endif
    #ifndef ADR_ANDROID__OS__SYSTEMPROPERTIES__GET_JAVA__LANG__STRING_
    #define ADR_ANDROID__OS__SYSTEMPROPERTIES__GET_JAVA__LANG__STRING_ 0
    #endif
    #ifndef ADR_ANDROID__OS__SYSTEMPROPERTIES__GET_JAVA__LANG__STRING_JAVA__LANG__STRING_
    #define ADR_ANDROID__OS__SYSTEMPROPERTIES__GET_JAVA__LANG__STRING_JAVA__LANG__STRING_ 0
    #endif
    #ifndef ADR_ANDROID__OS__SYSTEMPROPERTIES__GETBOOLEAN_JAVA__LANG__STRING_BOOLEAN_
    #define ADR_ANDROID__OS__SYSTEMPROPERTIES__GETBOOLEAN_JAVA__LANG__STRING_BOOLEAN_ 0
    #endif
    #ifndef ADR_ANDROID__OS__SYSTEMPROPERTIES__GETLONG_JAVA__LANG__STRING_LONG_
    #define ADR_ANDROID__OS__SYSTEMPROPERTIES__GETLONG_JAVA__LANG__STRING_LONG_ 0
    #endif
    #ifndef ADR_DALVIK__SYSTEM__BASEDEXCLASSLOADER___INIT__JAVA__LANG__STRING_JAVA__IO__FILE_JAVA__LANG__STRING_JAVA__LANG__CLASSLOADER_
    #define ADR_DALVIK__SYSTEM__BASEDEXCLASSLOADER___INIT__JAVA__LANG__STRING_JAVA__IO__FILE_JAVA__LANG__STRING_JAVA__LANG__CLASSLOADER_ 0
    #endif
    #ifndef ADR_DALVIK__SYSTEM__BASEDEXCLASSLOADER___INIT__JAVA__LANG__STRING_JAVA__LANG__STRING_JAVA__LANG__CLASSLOADER_JAVA__LANG__CLASSLOADER___
    #define ADR_DALVIK__SYSTEM__BASEDEXCLASSLOADER___INIT__JAVA__LANG__STRING_JAVA__LANG__STRING_JAVA__LANG__CLASSLOADER_JAVA__LANG__CLASSLOADER___ 0
    #endif
    #ifndef ADR_DALVIK__SYSTEM__BASEDEXCLASSLOADER___INIT__JAVA__LANG__STRING_JAVA__LANG__STRING_JAVA__LANG__CLASSLOADER_JAVA__LANG__CLASSLOADER___JAVA__LANG__CLASSLOADER___
    #define ADR_DALVIK__SYSTEM__BASEDEXCLASSLOADER___INIT__JAVA__LANG__STRING_JAVA__LANG__STRING_JAVA__LANG__CLASSLOADER_JAVA__LANG__CLASSLOADER___JAVA__LANG__CLASSLOADER___ 0
    #endif
    #ifndef ADR_DALVIK__SYSTEM__BASEDEXCLASSLOADER___INIT__JAVA__LANG__STRING_JAVA__LANG__STRING_JAVA__LANG__CLASSLOADER_JAVA__LANG__CLASSLOADER___JAVA__LANG__CLASSLOADER___BOOLEAN_
    #define ADR_DALVIK__SYSTEM__BASEDEXCLASSLOADER___INIT__JAVA__LANG__STRING_JAVA__LANG__STRING_JAVA__LANG__CLASSLOADER_JAVA__LANG__CLASSLOADER___JAVA__LANG__CLASSLOADER___BOOLEAN_ 0
    #endif
    #ifndef ADR_JAVA__LANG__CLASSLOADER__GETPACKAGE_JAVA__LANG__STRING_
    #define ADR_JAVA__LANG__CLASSLOADER__GETPACKAGE_JAVA__LANG__STRING_ 0
    #endif
    #ifndef ADR_COM__ANDROID__INTERNAL__OS__ZYGOTEINIT__FORKSYSTEMSERVER_JAVA__LANG__STRING_JAVA__LANG__STRING_COM__ANDROID__INTERNAL__OS__ZYGOTESERVER_
    #define ADR_COM__ANDROID__INTERNAL__OS__ZYGOTEINIT__FORKSYSTEMSERVER_JAVA__LANG__STRING_JAVA__LANG__STRING_COM__ANDROID__INTERNAL__OS__ZYGOTESERVER_ 0
    #endif
    #ifndef ADR_JAVA__LANG__RUNTIME__EXEC_JAVA__LANG__STRING_
    #define ADR_JAVA__LANG__RUNTIME__EXEC_JAVA__LANG__STRING_ 0
    #endif
    #ifndef ADR_JAVA__LANG__RUNTIME__EXEC_JAVA__LANG__STRING_JAVA__LANG__STRING___JAVA__IO__FILE_
    #define ADR_JAVA__LANG__RUNTIME__EXEC_JAVA__LANG__STRING_JAVA__LANG__STRING___JAVA__IO__FILE_ 0
    #endif
    #ifndef ADR_JAVA__LANG__RUNTIME__EXEC_JAVA__LANG__STRING___
    #define ADR_JAVA__LANG__RUNTIME__EXEC_JAVA__LANG__STRING___ 0
    #endif
    #ifndef ADR_JAVA__LANG__RUNTIME__EXEC_JAVA__LANG__STRING___JAVA__LANG__STRING___JAVA__IO__FILE_
    #define ADR_JAVA__LANG__RUNTIME__EXEC_JAVA__LANG__STRING___JAVA__LANG__STRING___JAVA__IO__FILE_ 0
    #endif
    // entry tracing segment for java.lang.ClassLoader.loadClass(java.lang.String)
    // and other functions
    if (event_ptr->context_ip == ADR_JAVA__LANG__CLASSLOADER__LOADCLASS_JAVA__LANG__STRING_ ||  // java.lang.ClassLoader.loadClass(java.lang.String)
        event_ptr->context_ip == ADR_ANDROID__APP__CONTEXTIMPL__CHECKPERMISSION_JAVA__LANG__STRING_INT_INT_ ||
        event_ptr->context_ip == ADR_ANDROID__APP__CONTEXTIMPL__CHECKPERMISSION_JAVA__LANG__STRING_INT_INT_ANDROID__OS__IBINDER_ ||
        event_ptr->context_ip == ADR_ANDROID__OS__SYSTEMPROPERTIES__GET_JAVA__LANG__STRING_ ||
        event_ptr->context_ip == ADR_ANDROID__OS__SYSTEMPROPERTIES__GET_JAVA__LANG__STRING_JAVA__LANG__STRING_ ||
        event_ptr->context_ip == ADR_ANDROID__OS__SYSTEMPROPERTIES__GETBOOLEAN_JAVA__LANG__STRING_BOOLEAN_ ||
        event_ptr->context_ip == ADR_ANDROID__OS__SYSTEMPROPERTIES__GETLONG_JAVA__LANG__STRING_LONG_ ||
        event_ptr->context_ip == ADR_DALVIK__SYSTEM__BASEDEXCLASSLOADER___INIT__JAVA__LANG__STRING_JAVA__IO__FILE_JAVA__LANG__STRING_JAVA__LANG__CLASSLOADER_ ||
        event_ptr->context_ip == ADR_DALVIK__SYSTEM__BASEDEXCLASSLOADER___INIT__JAVA__LANG__STRING_JAVA__LANG__STRING_JAVA__LANG__CLASSLOADER_JAVA__LANG__CLASSLOADER___ ||
        event_ptr->context_ip == ADR_DALVIK__SYSTEM__BASEDEXCLASSLOADER___INIT__JAVA__LANG__STRING_JAVA__LANG__STRING_JAVA__LANG__CLASSLOADER_JAVA__LANG__CLASSLOADER___JAVA__LANG__CLASSLOADER___ ||
        event_ptr->context_ip == ADR_DALVIK__SYSTEM__BASEDEXCLASSLOADER___INIT__JAVA__LANG__STRING_JAVA__LANG__STRING_JAVA__LANG__CLASSLOADER_JAVA__LANG__CLASSLOADER___JAVA__LANG__CLASSLOADER___BOOLEAN_ ||
        event_ptr->context_ip == ADR_JAVA__LANG__CLASSLOADER__GETPACKAGE_JAVA__LANG__STRING_ ||
        event_ptr->context_ip == ADR_COM__ANDROID__INTERNAL__OS__ZYGOTEINIT__FORKSYSTEMSERVER_JAVA__LANG__STRING_JAVA__LANG__STRING_COM__ANDROID__INTERNAL__OS__ZYGOTESERVER_ ||
        event_ptr->context_ip == ADR_JAVA__LANG__RUNTIME__EXEC_JAVA__LANG__STRING_ ||
        event_ptr->context_ip == ADR_JAVA__LANG__RUNTIME__EXEC_JAVA__LANG__STRING_JAVA__LANG__STRING___JAVA__IO__FILE_ ||
        event_ptr->context_ip == ADR_JAVA__LANG__RUNTIME__EXEC_JAVA__LANG__STRING___ ||
        event_ptr->context_ip == ADR_JAVA__LANG__RUNTIME__EXEC_JAVA__LANG__STRING___JAVA__LANG__STRING___JAVA__IO__FILE_) {
        u64 string_obj_adr = ctx->dx;

        u32 string_length;
        bpf_probe_read_user(&string_length, sizeof(string_length), (void *) string_obj_adr + 0x8);
        if (string_length >= 2) { // just to make BPF verifier happy
            string_length = string_length >> 1;
            string_length += 1;
        }
        event_ptr->debug = string_length;

        u32 to_read = sizeof(event_ptr->payload_bytes);
        if (string_length < to_read) {
            to_read = string_length;
        }
        bpf_probe_read_user_str(&event_ptr->payload_bytes, to_read, (void *) string_obj_adr + 0x10);
    }

    // ENTRY TRACING SEGMENT: *
    #ifndef ADR_ANDROID__OS__SYSTEMPROPERTIES__GETINT_JAVA__LANG__STRING_INT_
    #define ADR_ANDROID__OS__SYSTEMPROPERTIES__GETINT_JAVA__LANG__STRING_INT_ 0
    #endif
    #ifndef ADR_JAVA__UTIL__ZIP__ZIPFILE__OPEN_JAVA__LANG__STRING_INT_LONG_BOOLEAN_
    #define ADR_JAVA__UTIL__ZIP__ZIPFILE__OPEN_JAVA__LANG__STRING_INT_LONG_BOOLEAN_ 0
    #endif
    #ifndef ADR_DALVIK__SYSTEM__DEXFILE__OPENDEXFILENATIVE_JAVA__LANG__STRING_JAVA__LANG__STRING_INT_JAVA__LANG__CLASSLOADER_DALVIK__SYSTEM__DEXPATHLIST_ELEMENT___
    #define ADR_DALVIK__SYSTEM__DEXFILE__OPENDEXFILENATIVE_JAVA__LANG__STRING_JAVA__LANG__STRING_INT_JAVA__LANG__CLASSLOADER_DALVIK__SYSTEM__DEXPATHLIST_ELEMENT___ 0
    #endif
    // entry tracing segment for android.os.SystemProperties.getInt(java.lang.String,int)
    // and other functions
    if (event_ptr->context_ip == ADR_ANDROID__OS__SYSTEMPROPERTIES__GETINT_JAVA__LANG__STRING_INT_ ||
        event_ptr->context_ip == ADR_JAVA__UTIL__ZIP__ZIPFILE__OPEN_JAVA__LANG__STRING_INT_LONG_BOOLEAN_ ||
        event_ptr->context_ip == ADR_DALVIK__SYSTEM__DEXFILE__OPENDEXFILENATIVE_JAVA__LANG__STRING_JAVA__LANG__STRING_INT_JAVA__LANG__CLASSLOADER_DALVIK__SYSTEM__DEXPATHLIST_ELEMENT___) {
        u64 string_obj_adr = ctx->si;

        u32 string_length;
        bpf_probe_read_user(&string_length, sizeof(string_length), (void *) string_obj_adr + 0x8);
        if (string_length >= 2) { // just to make BPF verifier happy
            string_length = string_length >> 1;
            string_length += 1;
        }
        event_ptr->debug = string_length;

        u32 to_read = sizeof(event_ptr->payload_bytes);
        if (string_length < to_read) {
            to_read = string_length;
        }
        bpf_probe_read_user_str(&event_ptr->payload_bytes, to_read, (void *) string_obj_adr + 0x10);
    }

    // ENTRY TRACING SEGMENT: android.util.Base64.decode(java.lang.String,int)
    // entry tracing segment for android.util.Base64.decode(java.lang.String, int)
    if (event_ptr->context_ip == ADR_ANDROID__UTIL__BASE64__DECODE_JAVA__LANG__STRING_INT_) { // byte[] Base64.decode(String str, int flags)
        u64 string_obj_adr = ctx->si;

        u32 string_length;
        bpf_probe_read_user(&string_length, sizeof(string_length), (void *) string_obj_adr + 0x8);
        if (string_length >= 2) { // just to make BPF verifier happy
            string_length = string_length >> 1;
            string_length += 1;
        }

        // write first payload to first half of payload_bytes
        u32 to_read = sizeof(event_ptr->payload_bytes) - 32;
        if (string_length < to_read) {
            to_read = string_length;
        }
        bpf_probe_read_user_str(&event_ptr->payload_bytes, to_read, (void *) string_obj_adr + 0x10);
    }

    // RETURN TRACING SEGMENT: android.util.Base64.decode(java.lang.String,int)
    // return tracing segment for android.util.Base64.decode(java.lang.String, int)
    if (event_ptr->context_ip == ADR_ANDROID__UTIL__BASE64__DECODE_JAVA__LANG__STRING_INT_) { // byte[] Base64.decode(String str, int flags)
//        u64 string_obj_adr = ctx->r10;
//        u32 string_length;
//        bpf_probe_read_user(&string_length, sizeof(string_length), (void *) string_obj_adr + 0x8);
//        if (string_length >= 2) { // just to make BPF verifier happy
//            string_length = string_length >> 1;
//            string_length += 1;
//        }
//
//        // write payload to second half of payload_bytes
//        u32 to_read = sizeof(event_ptr->payload_bytes) - 32;
//        if (string_length < to_read) {
//            to_read = string_length;
//        }
        bpf_probe_read_user_str((void *)&event_ptr->payload_bytes + 32, sizeof(event_ptr->payload_bytes) - 32, (void *) ctx->r10 + 12);
    }

    // ENTRY TRACING SEGMENT: java.io.File.delete()
    // entry tracing segment for java.io.File.delete()
    if (event_ptr->context_ip == ADR_JAVA__IO__FILE__DELETE__) { // java.io.File.delete()
        bpf_send_signal(SIGSTOP);
        char msg1[] = "Sent signal SIGSTOP to process.";
        write_msg_to_event(msg1, event_ptr, sizeof(msg1));
        events.perf_submit(ctx, event_ptr, sizeof(*event_ptr));
        char msg2[] = "...";
        write_msg_to_event(msg2, event_ptr, sizeof(msg2));
    }

    // RETURN TRACING SEGMENT: java.io.File.getPath()
    // return tracing segment for java.io.File.getPath()
    if (event_ptr->context_ip == ADR_JAVA__IO__FILE__GETPATH__) { // java.io.File.getPath()
        u64 string_obj_adr = ctx->ax;
        event_ptr->debug = 1;

        u32 string_length;
        bpf_probe_read_user(&string_length, sizeof(string_length), (void *) string_obj_adr + 0x8);
        if (string_length >= 2) { // just to make BPF verifier happy
            string_length = string_length >> 1;
            string_length += 1;
        }

        // write first payload to first half of payload_bytes
        u32 to_read = sizeof(event_ptr->payload_bytes);
        if (string_length < to_read) {
            to_read = string_length;
        }
        bpf_probe_read_user_str(&event_ptr->payload_bytes, to_read, (void *) string_obj_adr + 0x10);
    }

    // ENTRY TRACING SEGMENT: *
    // entry tracing segment for    libcore.io.Linux.open(java.lang.String, int, int)
    //                              libcore.io.Linux.getenv(java.lang.String)
    #ifndef ADR_LIBCORE__IO__LINUX__OPEN_JAVA__LANG__STRING_INT_INT_
    #define ADR_LIBCORE__IO__LINUX__OPEN_JAVA__LANG__STRING_INT_INT_ 0
    #endif
    #ifndef ADR_LIBCORE__IO__LINUX__GETENV_JAVA__LANG__STRING_
    #define ADR_LIBCORE__IO__LINUX__GETENV_JAVA__LANG__STRING_ 0
    #endif
    if (event_ptr->context_ip == ADR_LIBCORE__IO__LINUX__OPEN_JAVA__LANG__STRING_INT_INT_ ||
        event_ptr->context_ip == ADR_LIBCORE__IO__LINUX__GETENV_JAVA__LANG__STRING_) {
        u64 string_obj_adr = ctx->dx;

        u32 string_length;
        bpf_probe_read_user(&string_length, sizeof(string_length), (void *) string_obj_adr + 0x8);
        if (string_length >= 2) { // just to make BPF verifier happy
            string_length = string_length >> 1;
            string_length += 1;
        }
        event_ptr->debug = string_length;

        u32 to_read = sizeof(event_ptr->payload_bytes);
        if (string_length < to_read) {
            to_read = string_length;
        }
        bpf_probe_read_user_str(&event_ptr->payload_bytes, to_read, (void *) string_obj_adr + 0x10);
    }
}