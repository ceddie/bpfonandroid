#!/usr/bin/env python3

from socket import AF_INET, inet_ntop
from struct import pack
import config
import helper
from helper import unsigned_to_signed64, EventType, print_event

TID_EVENT_DATA_DICT = {}  # tid -> function name -> event handler specific data


# ##### getdents64 ######
# https://linux.die.net/man/2/getdents64
# int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
#   The system call getdents() reads several linux_dirent structures from the
#   directory referred to by the open file descriptor fd into the buffer pointed
#   to by dirp. The argument count specifies the size of that buffer.
def getdents64_event_handler(static_info, e):
    payload_string = bytearray(e.payload_bytes).split(b'\x00')[0]
    if e.type == EventType.RETURN_EVENT:
        pass
    else:
        print_event(static_info, e, b"%s" % payload_string)


# ##### openat ######
# https://linux.die.net/man/2/openat
# int openat(int dirfd, const char *pathname, int flags, mode_t mode);
# On success, openat() returns a new file descriptor.
# On error, -1 is returned and errno is set to indicate the error.
def openat_syscall_event_handler(static_info, e):
    ret = unsigned_to_signed64(e.ret_value)
    if ret >= 0:
        fd_s = ret
        err = 0
    else:
        fd_s = -1
        err = - ret
    payload_string = bytearray(e.payload_bytes).split(b'\x00')[0]
    print_event(static_info, e, b"(fd_s=%d, err=%d) %s" % (fd_s, err, payload_string))


# ##### execve (Final-Event) ######
# https://linux.die.net/man/2/execve
# int execve(const char *filename, char *const argv[], char *const envp[]);
# On success, execve() does not return, on error -1 is returned, and errno is set appropriately.
def process_execve_syscall_final_event(static_info, e):
    tid_store_dict = TID_EVENT_DATA_DICT.get(e.tid, None)
    if not tid_store_dict:
        helper.LOGGER.info("DEBUG: tid_store_dict is empty for a final event")
        return
    stored_value = tid_store_dict.get(static_info['name'], None)
    if not stored_value:
        helper.LOGGER.info("DEBUG: store_value is empty for a final event")
        return
    print_event(static_info, e, b"%s" % stored_value)
    del tid_store_dict[static_info['name']]


# ##### execve (Entry-Event) ######
# https://linux.die.net/man/2/execve
# int execve(const char *filename, char *const argv[], char *const envp[]);
# On success, execve() does not return, on error -1 is returned, and errno is set appropriately.
def process_execve_syscall_entry_event(static_info, e):
    payload_string = bytearray(e.payload_bytes).split(b'\x00')[0]
    if config.DEBUG:
        helper.LOGGER.info("DEBUG: Partial event: %s" % payload_string)
    interim_data_dict = TID_EVENT_DATA_DICT.get(e.tid, None)
    if not interim_data_dict:
        # TID_EVENT_DATA_DICT is empty for this tid; initialize empty dict
        TID_EVENT_DATA_DICT[e.tid] = {}
        interim_data_dict = TID_EVENT_DATA_DICT[e.tid]
    execve_stored_value = interim_data_dict.get(static_info['name'], None)
    if not execve_stored_value:
        # this event is the first execve interim event for this tid
        if config.DEBUG:
            helper.LOGGER.info("DEBUG: first execve interim event for this tid")
        interim_data_dict[static_info['name']] = payload_string
    else:
        # a stored value exists for execve for this tid
        if config.DEBUG:
            helper.LOGGER.info("DEBUG: a stored value exists for execve for this tid")
        interim_data_dict[static_info['name']] += b' ' + payload_string


# ##### execve ######
def execve_syscall_event_handler(static_info, e):
    if e.type == EventType.ENTRY_EVENT:
        process_execve_syscall_entry_event(static_info, e)
    else:
        process_execve_syscall_final_event(static_info, e)


# ##### android_getaddrinfofornet ######
# https://android.googlesource.com/platform/bionic/+/dd878fe129bb128fb28577c6ccc3fbf04addf898/libc/dns/include/resolv_netid.h
# int android_getaddrinfofornet(const char * node, const char * service, const struct addrinfo * hints,
#   unsigned netid, unsigned ???, struct addrinfo ** res)
def getaddrinfofornet_event_handler(static_info, e):
    print_event(static_info, e, b"%s" % (e.arg1_data))


# ##### connect ######
# https://linux.die.net/man/3/connect
# int connect(int socket, const struct sockaddr *address, socklen_t address_len)
# address
#   Points to a sockaddr structure containing the peer address.
#   The length and format of the address depend on the address family of the socket.
# address_len
#   Specifies the length of the sockaddr structure pointed to by the address argument.
#
# struct sockaddr {
#    unsigned short   sa_family;
#    char             sa_data[14];
# };
def connect_syscall_event_handler(static_info, e):
    payload_string = bytearray(e.payload_bytes).split(b'\x00')[0]
    print_event(static_info, e, b"%s" % (payload_string))


# ##### tcp_v4_connect ######
# https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_ipv4.c
# int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
def tcp_v4_connect_event_handler(static_info, e):
    import ctypes
    from ctypes import Structure

    class TcpV4ConnectData(Structure):
        _pack_ = 1
        _fields_ = [("saddr", ctypes.c_uint32),
                    ("daddr", ctypes.c_uint32),
                    ("lport", ctypes.c_uint16),
                    ("dport", ctypes.c_uint16)]

    data = TcpV4ConnectData.from_buffer(e.payload_bytes)
    dest_ip = inet_ntop(AF_INET, pack("I", data.daddr)).encode()
    src_ip = inet_ntop(AF_INET, pack("I", data.saddr)).encode()
    print_event(static_info, e, b"%s:%d -> %s:%d" % (src_ip, data.lport, dest_ip, data.dport))


# ##### android.util.Base64.decode(java.lang.String,int) ######
# https://developer.android.com/reference/android/util/Base64#decode(java.lang.String,%20int)
# byte[] Base64.decode(String str, int flags)
#   * String str: the input String to decode, which is converted to bytes using the default charset.
#   * int flags: controls certain features of the decoded output. Pass DEFAULT to decode standard Base64.
def base64_decode_event_handler(static_info, e):
    payload_split = bytearray(e.payload_bytes).split(b'\x00')
    payload1_bytes = payload_split[0]
    payload2_bytes = b''.join(payload_split[1:])
    print_event(static_info, e, b"%s -> %s" % (payload1_bytes, payload2_bytes))


# ##### java.io.File.getPath() ######
def file_getpath_event_handler(static_info, e):
    payload_string = bytearray(e.payload_bytes).split(b'\x00')[0]
    print_event(static_info, e, b"%s" % payload_string)
