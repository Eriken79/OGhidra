# GhidraMCP Tool Capabilities

This document provides a comprehensive list of all available tools in the GhidraMCP API.

## Tool Overview

| Tool | Description | Parameters | Return Type | Test Status |
|------|-------------|------------|-------------|-------------|
| analyze_function | Analyze a function, including its decompiled code and all functions it calls. | address | str | ✅ Success |
| check_health | Check if the GhidraMCP server is reachable and responding. |  | bool | ✅ Success |
| decompile_function | Decompile a specific function by name and return the decompiled C code. | name, offset, limit | str | ✅ Success |
| decompile_function_by_address | Decompile a function by address and return the decompiled C code. | address, offset, limit | str | ✅ Success |
| disassemble_function | Get assembly code (address: instruction; comment) for a function. | address | List[str] | ✅ Success |
| format_table_scan_results | Format the scan results for human-readable output. | tables, max_entries_shown | str | ✅ Success |
| get_current_address | Get the address currently selected by the user. |  | str | ✅ Success |
| get_current_function | Get the function currently selected by the user. |  | str | ✅ Success |
| get_current_program_info | Get structured information about the currently active program. |  | Dict[str, str] | ✅ Success |
| get_function_by_address | Get a function by its address. | address | str | ✅ Success |
| get_function_xrefs | List x-refs to a function by `name`. If an address is mistakenly passed, | name, offset, limit | Unknown | ✅ Success |
| get_xrefs_from | List all x-refs *from* `address`. | address, offset, limit | Unknown | ✅ Success |
| get_xrefs_to | List all x-refs *to* `address`. Returns list/str depending on API. | address, offset, limit | Unknown | ✅ Success |
| health_check | Check if the GhidraMCP server is available. |  | bool | ✅ Success |
| instances_current | Get information about the currently active Ghidra instance. |  | str | ✅ Success |
| instances_discover | Discover Ghidra instances on a specific host and port range. | host, start_port, end_port | str | ✅ Success |
| instances_list | List all active Ghidra instances and auto-discover new ones on localhost. |  | str | ✅ Success |
| instances_use | Switch the active Ghidra instance to the specified port. | port | str | ✅ Success |
| list_classes | List all namespace/class names in the program with pagination. | offset, limit | List[str] | ✅ Success |
| list_data_items | List defined data labels and their values with pagination. | offset, limit | List[str] | ✅ Success |
| list_exports | List exported functions/symbols with pagination. | offset, limit | List[str] | ✅ Success |
| list_functions | List all functions in the database with pagination. | offset, limit | List[str] | ✅ Success |
| list_imports | List imported symbols in the program with pagination. | offset, limit | List[str] | ✅ Success |
| list_methods | List all function names in the program with pagination. | offset, limit | List[str] | ✅ Success |
| list_namespaces | List all non-global namespaces in the program with pagination. | offset, limit | List[str] | ✅ Success |
| list_segments | List all memory segments in the program with pagination. | offset, limit | List[str] | ✅ Success |
| list_strings | List defined strings (or search with substring filter). | offset, limit, filter | List[str] | ✅ Success |
| read_bytes | Read raw bytes from memory at the specified address. | address, length, format | str | ✅ Success |
| rename_data | Rename a data label at the specified address. | address, new_name | str | ✅ Success |
| rename_function | Rename a function by its current name to a new user-defined name. | old_name, new_name | str | ✅ Success |
| rename_function_by_address | Rename a function by its address. | function_address, new_name | str | ✅ Success |
| rename_variable | Rename a local variable within a function. | function_name, old_name, new_name | str | ✅ Success |
| scan_function_pointer_tables | Scan the binary for function pointer tables without LLM assistance. | min_table_entries, pointer_size, max_scan_size, alignment | List[Dict] | ✅ Success |
| search_functions_by_name | Search for functions whose name contains the given substring. | query, offset, limit | List[str] | ✅ Success |
| set_decompiler_comment | Set a comment for a given address in the function pseudocode. | address, comment | str | ✅ Success |
| set_disassembly_comment | Set a comment for a given address in the function disassembly. | address, comment | str | ✅ Success |
| set_function_prototype | Set a function's prototype. | function_address, prototype | str | ✅ Success |
| set_local_variable_type | Set a local variable's type. | function_address, variable_name, new_type | str | ✅ Success |

## Detailed Tool Documentation

### analyze_function

Analyze a function, including its decompiled code and all functions it calls.
If no address is provided, uses the current function.

Args:
    address: Function address (optional)
    
Returns:
    Comprehensive function analysis including decompiled code and referenced functions

**Signature:**
```python
analyze_function(address: str = None) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| address | No | None | <class 'str'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
=== ANALYSIS OF FUNCTION AT 1400030e0 ===

[Total Lines: 5] [Showing Lines: 1-5]
undefined * FUN_1400030e0(void)

{
  return &DAT_140179948;
}

=== KEY REFERENCED FUNCTIONS (SAMPLE) ===

--- Function: FUN_1400030e0 ---
[Total Lines: 5] [Showing Lines: 1-5]
undefined * FUN_1400030e0(void)

{
  return...
```

---

### check_health

Check if the GhidraMCP server is reachable and responding.

Returns:
    True if GhidraMCP is healthy, False otherwise

**Signature:**
```python
check_health() -> bool
```

**Parameters:**
No parameters.

**Test Results:**
- Status: ✅ Success
- Return Type: bool
- Sample Result:
```
True
```

---

### decompile_function

Decompile a specific function by name and return the decompiled C code.

Args:
    name: Function name
    offset: Line offset (default: 0)
    limit: Max lines to return (default: 500)
    
Returns:
    Decompiled C code

**Signature:**
```python
decompile_function(name: str, offset: int = 0, limit: int = 500) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| name | Yes | None | <class 'str'> |
| offset | No | 0 | <class 'int'> |
| limit | No | 500 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
Function not found
```

---

### decompile_function_by_address

Decompile a function by address and return the decompiled C code.

Args:
    address: Function address (e.g., "0x401000")
    offset: Line offset (default: 0)
    limit: Max lines to return (default: 500)
    
Returns:
    Decompiled function

**Signature:**
```python
decompile_function_by_address(address: str, offset: int = 0, limit: int = 500) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| address | Yes | None | <class 'str'> |
| offset | No | 0 | <class 'int'> |
| limit | No | 500 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
[Total Lines: 5] [Showing Lines: 1-5]
undefined * FUN_1400030e0(void)

{
  return &DAT_140179948;
}
```

---

### disassemble_function

Get assembly code (address: instruction; comment) for a function.

Args:
    address: Function address
    
Returns:
    Disassembled function

**Signature:**
```python
disassemble_function(address: str) -> List[str]
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| address | Yes | None | <class 'str'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
1400030e0: LEA RAX,[0x140179948] 
1400030e7: RET 
```

---

### format_table_scan_results

Format the scan results for human-readable output.

Args:
    tables: List of table dicts from scan_function_pointer_tables
    max_entries_shown: Maximum entries to show per table (default: 10)
    
Returns:
    Formatted string with table information

**Signature:**
```python
format_table_scan_results(tables: List[Dict], max_entries_shown: int = 10) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| tables | Yes | None | typing.List[typing.Dict] |
| max_entries_shown | No | 10 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
Found 1 function pointer table(s):

## Table 1: 4198400 (5 entries)

```

---

### get_current_address

Get the address currently selected by the user.

Returns:
    Current address

**Signature:**
```python
get_current_address() -> str
```

**Parameters:**
No parameters.

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
14017a870
```

---

### get_current_function

Get the function currently selected by the user.

Returns:
    Current function

**Signature:**
```python
get_current_function() -> str
```

**Parameters:**
No parameters.

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
No function at current location: 14017a870
```

---

### get_current_program_info

Get structured information about the currently active program.

Returns:
    Dict containing 'name', 'project', 'port', etc.

**Signature:**
```python
get_current_program_info() -> Dict[str, str]
```

**Parameters:**
No parameters.

**Test Results:**
- Status: ✅ Success
- Return Type: dict
- Sample Result:
```
{'name': 'xilcurl.exe', 'project': 'vivado_oghidra', 'port': '8080', 'url': 'http://localhost:8080', 'plugin_version': 'Custom-OGhidraMCP'}
```

---

### get_function_by_address

Get a function by its address.

Args:
    address: Function address
    
Returns:
    Function information

**Signature:**
```python
get_function_by_address(address: str) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| address | Yes | None | <class 'str'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
Function: FUN_1400030e0 at 1400030e0
Signature: undefined * __fastcall FUN_1400030e0(void)
Entry: 1400030e0
Body: 1400030e0 - 1400030e7
```

---

### get_function_xrefs

List x-refs to a function by `name`. If an address is mistakenly passed,
we treat it as address form and call get_xrefs_to instead.

**Signature:**
```python
get_function_xrefs(name: str, offset: int = 0, limit: int = 100)
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| name | Yes | None | <class 'str'> |
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
Function or symbol not found: [Total: 3221] [Showing: 1-100] [Next: offset=100, limit=100]
```

---

### get_xrefs_from

List all x-refs *from* `address`.

**Signature:**
```python
get_xrefs_from(address: str, offset: int = 0, limit: int = 100)
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| address | Yes | None | <class 'str'> |
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
[Total: 1] [Showing: 1-1]
To 140179948 to data DAT_140179948 [DATA]
```

---

### get_xrefs_to

List all x-refs *to* `address`. Returns list/str depending on API.

**Signature:**
```python
get_xrefs_to(address: str, offset: int = 0, limit: int = 100)
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| address | Yes | None | <class 'str'> |
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
[Total: 2] [Showing: 1-2]
From 140003861 in parseStringWithVsscanf [UNCONDITIONAL_CALL]
From 1400ec185 in FUN_1400ec178 [UNCONDITIONAL_CALL]
```

---

### health_check

Check if the GhidraMCP server is available.

Returns:
    True if the server is available, False otherwise

**Signature:**
```python
health_check() -> bool
```

**Parameters:**
No parameters.

**Test Results:**
- Status: ✅ Success
- Return Type: bool
- Sample Result:
```
True
```

---

### instances_current

Get information about the currently active Ghidra instance.

Returns:
    Instance information

**Signature:**
```python
instances_current() -> str
```

**Parameters:**
No parameters.

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
=== Current Instance: Port 8080 ===
Binary: xilcurl.exe
Project: vivado_oghidra
URL: http://localhost:8080
Plugin Version: Custom-OGhidraMCP
```

---

### instances_discover

Discover Ghidra instances on a specific host and port range.

Args:
    host: Hostname to scan (default: localhost)
    start_port: Start of port range
    end_port: End of port range
    
Returns:
    Discovery results

**Signature:**
```python
instances_discover(host: str = 'localhost', start_port: int = 8192, end_port: int = 8200) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| host | No | localhost | <class 'str'> |
| start_port | No | 8192 | <class 'int'> |
| end_port | No | 8200 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
=== Active Ghidra Instances ===
• Port 8080: xilcurl.exe [vivado_oghidra] (CURRENT)

Use 'instances_use(port=...)' to switch between instances.
```

---

### instances_list

List all active Ghidra instances and auto-discover new ones on localhost.

Returns:
    Formatted string listing instances and their status

**Signature:**
```python
instances_list() -> str
```

**Parameters:**
No parameters.

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
=== Active Ghidra Instances ===
• Port 8080: xilcurl.exe [vivado_oghidra] (CURRENT)

Use 'instances_use(port=...)' to switch between instances.
```

---

### instances_use

Switch the active Ghidra instance to the specified port.

Args:
    port: The port number of the instance to use
    
Returns:
    Confirmation message

**Signature:**
```python
instances_use(port: int) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| port | Yes | None | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
Switched to Ghidra instance on port 8080 analyzing 'xilcurl.exe'
```

---

### list_classes

List all namespace/class names in the program with pagination.

Args:
    offset: Offset to start from
    limit: Maximum number of results
    
Returns:
    List of class names

**Signature:**
```python
list_classes(offset: int = 0, limit: int = 100) -> List[str]
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
[Total: 149] [Showing: 1-10] [Next: offset=10, limit=10]
ADVAPI32.DLL
API-MS-WIN-CRT-CONIO-L1-1-0.DLL
API-MS-WIN-CRT-CONVERT-L1-1-0.DLL
API-MS-WIN-CRT-ENVIRONMENT-L1-1-0.DLL
... truncated ...
```

---

### list_data_items

List defined data labels and their values with pagination.

Args:
    offset: Offset to start from
    limit: Maximum number of results
    
Returns:
    List of data items

**Signature:**
```python
list_data_items(offset: int = 0, limit: int = 100) -> List[str]
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
[Total: 32324] [Showing: 1-10] [Next: offset=10, limit=10]
140000000: IMAGE_DOS_HEADER_140000000 = 
140000080: (unnamed) = 
1400000f8: IMAGE_NT_HEADERS64_1400000f8 = 
140000200: IMAGE_SECTION_HEADER_140000200 = 
... truncated ...
```

---

### list_exports

List exported functions/symbols with pagination.

Args:
    offset: Offset to start from
    limit: Maximum number of results
    
Returns:
    List of exported symbols

**Signature:**
```python
list_exports(offset: int = 0, limit: int = 100) -> List[str]
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
[Total: 119] [Showing: 1-10] [Next: offset=10, limit=10]
curl_strequal -> 14000f580
Ordinal_55 -> 14000f580
curl_strnequal -> 14000f5a0
Ordinal_56 -> 14000f5a0
... truncated ...
```

---

### list_functions

List all functions in the database with pagination.

Args:
    offset: Offset to start from (default: 0)
    limit: Maximum number of results (default: 100)

Returns:
    List of functions with pagination metadata

**Signature:**
```python
list_functions(offset: int = 0, limit: int = 100) -> List[str]
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
[Total: 3221] [Showing: 1-10] [Next: offset=10, limit=10]
setFileBinaryMode at 140001000
extractBaseFilenameFromPath at 140001020
dumpBinaryDataToFileStream at 140001090
curlDebugTraceCallback at 140001250
... truncated ...
```

---

### list_imports

List imported symbols in the program with pagination.

Args:
    offset: Offset to start from
    limit: Maximum number of results
    
Returns:
    List of imported symbols

**Signature:**
```python
list_imports(offset: int = 0, limit: int = 100) -> List[str]
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
[Total: 192] [Showing: 1-10] [Next: offset=10, limit=10]
shutdown -> EXTERNAL:00000001 [Refs: 2] [Callers: 1400ed230, FUN_140083e40]
gethostname -> EXTERNAL:00000002 [Refs: 2] [Callers: 1400ed238, fetchShortHostname]
sendto -> EXTERNAL:00000003 [Refs: 10] [Callers: 1400ed240, handleTftpTxAckAndSendDataBlock, handleTftpTxAckAndSendDataBlock, handleTftpTxAckAndSendDataBlock, handleTftpTxAckAndSendDataBlock, ...]
recvfrom -> EXTERNAL:00000004 [Refs: 2] [Callers: 1400ed248, receiveAndHandleTftpPacket]
... truncated ...
```

---

### list_methods

List all function names in the program with pagination.

Args:
    offset: Offset to start from
    limit: Maximum number of results
    
Returns:
    List of function names

**Signature:**
```python
list_methods(offset: int = 0, limit: int = 100) -> List[str]
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
[Total: 3221] [Showing: 1-10] [Next: offset=10, limit=10]
setFileBinaryMode
extractBaseFilenameFromPath
dumpBinaryDataToFileStream
curlDebugTraceCallback
... truncated ...
```

---

### list_namespaces

List all non-global namespaces in the program with pagination.

Args:
    offset: Offset to start from
    limit: Maximum number of results
    
Returns:
    List of namespaces

**Signature:**
```python
list_namespaces(offset: int = 0, limit: int = 100) -> List[str]
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
[Total: 149] [Showing: 1-10] [Next: offset=10, limit=10]
ADVAPI32.DLL
API-MS-WIN-CRT-CONIO-L1-1-0.DLL
API-MS-WIN-CRT-CONVERT-L1-1-0.DLL
API-MS-WIN-CRT-ENVIRONMENT-L1-1-0.DLL
... truncated ...
```

---

### list_segments

List all memory segments in the program with pagination.

Args:
    offset: Offset to start from
    limit: Maximum number of results
    
Returns:
    List of memory segments

**Signature:**
```python
list_segments(offset: int = 0, limit: int = 100) -> List[str]
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
[Total: 8] [Showing: 1-8]
Headers: 140000000 - 1400003ff
.text: 140001000 - 1400ec7ff
.rdata: 1400ed000 - 14015c1ff
.data: 14015d000 - 140179977
... truncated ...
```

---

### list_strings

List defined strings (or search with substring filter).

Args:
    offset: Pagination offset
    limit: Maximum number of results
    filter: Optional substring to restrict results (alias: string_search)

Returns:
    List of strings (raw API response)

**Signature:**
```python
list_strings(offset: int = 0, limit: int = 100, filter: str | None = None) -> List[str]
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |
| filter | No | None | str | None |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
[Total: 6718] [Showing: 1-10] [Next: offset=10, limit=10]
1400ed740: "%02d:%02d:%02d.%06ld "
1400ed768: "Failed to create/open output"
1400ed788: "%s%s "
1400ed790: "[data not shown]\n"
... truncated ...
```

---

### read_bytes

Read raw bytes from memory at the specified address.

Args:
    address: Starting address in hex format (e.g. "0x1400010a0")
    length: Number of bytes to read (1-4096, default: 16)
    format: "hex" for hex dump with ASCII representation, 
            "raw" for base64 encoded bytes
    
Returns:
    Hex dump string or base64-encoded raw bytes

**Signature:**
```python
read_bytes(address: str, length: int = 16, format: str = 'hex') -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| address | Yes | None | <class 'str'> |
| length | No | 16 | <class 'int'> |
| format | No | hex | <class 'str'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
1400030e0: 48 8D 05 61 68 17 00 C3 CC CC CC CC CC CC CC CC  |H..ah...........|
```

---

### rename_data

Rename a data label at the specified address.

Args:
    address: Data address
    new_name: New data name
    
Returns:
    Result of the rename operation

**Signature:**
```python
rename_data(address: str, new_name: str) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| address | Yes | None | <class 'str'> |
| new_name | Yes | None | <class 'str'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
Rename data attempted
```

---

### rename_function

Rename a function by its current name to a new user-defined name.

Args:
    old_name: Current function name
    new_name: New function name
    
Returns:
    Result of the rename operation

**Signature:**
```python
rename_function(old_name: str, new_name: str) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| old_name | Yes | None | <class 'str'> |
| new_name | Yes | None | <class 'str'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
Rename failed
```

---

### rename_function_by_address

Rename a function by its address.

Args:
    function_address: Function address
    new_name: New name
    
Returns:
    Result of the rename operation

**Signature:**
```python
rename_function_by_address(function_address: str, new_name: str) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| function_address | Yes | None | <class 'str'> |
| new_name | Yes | None | <class 'str'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
Function renamed successfully
```

---

### rename_variable

Rename a local variable within a function.

Args:
    function_name: Function name
    old_name: Current variable name
    new_name: New variable name
    
Returns:
    Result of the rename operation

**Signature:**
```python
rename_variable(function_name: str, old_name: str, new_name: str) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| function_name | Yes | None | <class 'str'> |
| old_name | Yes | None | <class 'str'> |
| new_name | Yes | None | <class 'str'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
Function not found
```

---

### scan_function_pointer_tables

Scan the binary for function pointer tables without LLM assistance.

Algorithm:
1. Get all memory segments and identify data segments
2. Get all known function addresses to build a lookup set
3. Scan data segments for pointer-aligned sequences
4. Identify consecutive values that match valid function addresses
5. Return list of suspected tables with their entries

Args:
    min_table_entries: Minimum consecutive function pointers to qualify as a table (default: 3)
    pointer_size: Size of pointers in bytes (8 for x64, 4 for x86)
    max_scan_size: Maximum bytes to scan per segment
    alignment: Expected pointer alignment
    
Returns:
    List of dicts: {
        'table_address': str,
        'entry_count': int,
        'entries': [{'offset': int, 'pointer': str, 'function_name': str}, ...]
    }

**Signature:**
```python
scan_function_pointer_tables(min_table_entries: int = 3, pointer_size: int = 8, max_scan_size: int = 524288, alignment: int = 8) -> List[Dict]
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| min_table_entries | No | 3 | <class 'int'> |
| pointer_size | No | 8 | <class 'int'> |
| max_scan_size | No | 524288 | <class 'int'> |
| alignment | No | 8 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
```

---

### search_functions_by_name

Search for functions whose name contains the given substring.

Args:
    query: Search query
    offset: Offset to start from
    limit: Maximum number of results
    
Returns:
    List of matching functions

**Signature:**
```python
search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> List[str]
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| query | Yes | None | <class 'str'> |
| offset | No | 0 | <class 'int'> |
| limit | No | 100 | <class 'int'> |

**Test Results:**
- Status: ✅ Success
- Return Type: list
- Sample Result:
```
No functions matching '[Total: 3221] [Showing: 1-100] [Next: offset=100, limit=100]'
```

---

### set_decompiler_comment

Set a comment for a given address in the function pseudocode.

Args:
    address: Address
    comment: Comment
    
Returns:
    Result of the operation

**Signature:**
```python
set_decompiler_comment(address: str, comment: str) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| address | Yes | None | <class 'str'> |
| comment | Yes | None | <class 'str'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
Comment set successfully
```

---

### set_disassembly_comment

Set a comment for a given address in the function disassembly.

Args:
    address: Address
    comment: Comment
    
Returns:
    Result of the operation

**Signature:**
```python
set_disassembly_comment(address: str, comment: str) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| address | Yes | None | <class 'str'> |
| comment | Yes | None | <class 'str'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
Comment set successfully
```

---

### set_function_prototype

Set a function's prototype.

Args:
    function_address: Function address
    prototype: Function prototype
    
Returns:
    Result of the operation

**Signature:**
```python
set_function_prototype(function_address: str, prototype: str) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| function_address | Yes | None | <class 'str'> |
| prototype | Yes | None | <class 'str'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
Function prototype set successfully
```

---

### set_local_variable_type

Set a local variable's type.

Args:
    function_address: Function address
    variable_name: Variable name
    new_type: New type
    
Returns:
    Result of the operation

**Signature:**
```python
set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str
```

**Parameters:**
| Name | Required | Default | Type |
|------|----------|---------|------|
| function_address | Yes | None | <class 'str'> |
| variable_name | Yes | None | <class 'str'> |
| new_type | Yes | None | <class 'str'> |

**Test Results:**
- Status: ✅ Success
- Return Type: str
- Sample Result:
```
Setting variable type: local_10 to char* in function at 1400030e0

Type not found directly: char*

Result: Failed to set variable type
```

---

## Calling Tools from AI Agent

When using these tools from the AI agent, use the following format:

```
EXECUTE: tool_name(param1="value1", param2="value2")
```

For example:

```
EXECUTE: decompile_function(name="main")
```

## Generated Documentation

This documentation was automatically generated by the ToolCapabilityTester on 2026-04-08 11:44:37.
