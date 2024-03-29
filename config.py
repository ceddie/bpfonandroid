TIMEOUT = 120
NUMBER_STACK_LEVELS = 20
DEBUG = False
ENABLE_AAPI_RETURN_TRACING = True
ENABLE_CHECKING_AAPI_RETURN_ADDRESSES = True
CONFIG_FILE = 'functions.json'
BPF_PROGRAM_TEMPLATE_FILE = "./bpf.c"
CACHE_FOLDER = 'cache/'
DATA_FOLDER = '/mnt/data'
OUTPUT_FOLDER = "./output"
ENTRY_TRACE_FUNCTION_WITHOUT_OVERRIDE = "syscall__generic_entry_trace_function_without_override"
RETURN_TRACE_FUNCTION_WITHOUT_OVERRIDE = "generic_return_trace_function_without_override"
TRACING_SEGMENTS_WITHOUT_OVERRIDE_FILE = 'tracing_segments_without_override.c'
ENTRY_TRACE_FUNCTION_WITH_OVERRIDE = "syscall__generic_entry_trace_function_with_override"
RETURN_TRACE_FUNCTION_WITH_OVERRIDE = "generic_return_trace_function_with_override"
TRACING_SEGMENTS_WITH_OVERRIDE_FILE = 'tracing_segments_with_override.c'
