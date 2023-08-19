#!/bin/sh

# Report missing kernel features
# from https://github.com/iovisor/bpftrace/blob/master/scripts/check_kernel_features.sh
# adapted by ceddie
# Usage: ./check_kernel_features.sh [PATH_TO_KERNEL_CONFIG]

echo "Checking eBPF-related kernel config..."
echo ""

set -e
set -u

err=0
config=''

# Find kernel config
for c in "$@" "/boot/config-$(uname -r)" "/boot/config" "/proc/config.gz"; do
    if [ -r "$c" ]; then
        config="$c"
        break
    fi
done

if [ -z "$config" ]; then
    echo "Could not find kernel config, please supply it as argument." >&2
    exit 1
fi

# Check feature
check_opt() {
    if ! zgrep -qE "^${1}[[:space:]]*=[[:space:]]*[y|Y]" "$config"; then
        err=1
        echo "  * Option ${1} not set" >&2
    fi
}

check_opt 'CONFIG_BPF'
check_opt 'CONFIG_BPF_EVENTS'
check_opt 'CONFIG_BPF_JIT'
check_opt 'CONFIG_BPF_SYSCALL'
check_opt 'CONFIG_HAVE_EBPF_JIT'
check_opt 'CONFIG_HAVE_KPROBES'
check_opt 'CONFIG_KPROBES'
check_opt 'CONFIG_KPROBE_EVENTS'
check_opt 'CONFIG_ARCH_SUPPORTS_UPROBES'
check_opt 'CONFIG_UPROBES'
check_opt 'CONFIG_UPROBE_EVENTS'
check_opt 'CONFIG_DEBUG_FS'
check_opt 'CONFIG_BPF_KPROBE_OVERRIDE'
check_opt 'CONFIG_FUNCTION_ERROR_INJECTION'

echo ""
# Status report
if [ $err -eq 0 ]; then
    echo "All required features present! BPFonAndroid should work."
else
    echo "Missing some features, but BPFonAndroid might still work. (See https://github.com/iovisor/bcc/blob/master/docs/kernel_config.md for more details.)"
fi

exit $err
