import inspect
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock

from src.config import GhidraMCPConfig
from src.ghidra_client import (
    AbstractGhidraClient,
    GhidraMCPClient,
    PyGhidraClient,
)


def _make_http_client() -> GhidraMCPClient:
    client = GhidraMCPClient.__new__(GhidraMCPClient)
    AbstractGhidraClient.__init__(client, GhidraMCPConfig(), None)
    client._http_get_lines = MagicMock(return_value=["line1", "line2"])  # type: ignore[attr-defined]
    client._http_post_text = MagicMock(return_value="post-ok")  # type: ignore[attr-defined]
    return client


def _make_pyghidra_client(program=None) -> PyGhidraClient:
    client = PyGhidraClient.__new__(PyGhidraClient)
    AbstractGhidraClient.__init__(client, GhidraMCPConfig(), None)
    client.api_version = None
    client.active_instances = {}
    client.current_instance_port = None
    client.default_port = None
    client._request_lock = None
    client._pyghidra = SimpleNamespace(transaction=None)
    client._project = None
    client._program = program
    client._decomp = None
    client._decomp_monitor = object()
    client._project_ctx = None
    client._program_ctx = None
    client._program_consumer = None
    client._open_program_cm = None
    client._DefinedStringIterator = None
    return client


class FakeAddress:
    def __init__(self, value: str | int):
        if isinstance(value, int):
            self._offset = value
        else:
            normalized = value.lower().removeprefix("0x")
            self._offset = int(normalized, 16)

    def __str__(self):
        return f"{self._offset:x}"

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return isinstance(other, FakeAddress) and self._offset == other._offset

    def __hash__(self):
        return hash(self._offset)

    def getOffset(self):
        return self._offset

    def add(self, offset: int):
        return FakeAddress(self._offset + offset)


class FakeFunction:
    def __init__(self, name: str, entry: str):
        self._name = name
        self._entry = FakeAddress(entry)

    def getName(self):
        return self._name

    def getEntryPoint(self):
        return self._entry


class FakeFunctionManager:
    def __init__(self, functions, containing=None, at_map=None):
        self._functions = list(functions)
        self._containing = containing or {}
        self._at_map = at_map or {str(func.getEntryPoint()): func for func in self._functions}

    def getFunctions(self, _forward):
        return list(self._functions)

    def getFunctionAt(self, addr):
        return self._at_map.get(str(addr))

    def getFunctionContaining(self, addr):
        return self._containing.get(str(addr))


class FakeMemoryBlock:
    def __init__(self, name: str, start: str, end: str):
        self._name = name
        self._start = FakeAddress(start)
        self._end = FakeAddress(end)

    def getName(self):
        return self._name

    def getStart(self):
        return self._start

    def getEnd(self):
        return self._end


class FakeMemory:
    def __init__(self, blocks):
        self._blocks = list(blocks)

    def getBlocks(self):
        return list(self._blocks)


class FakeReferenceType:
    def __init__(self, name: str):
        self._name = name

    def toString(self):
        return self._name


class FakeReference:
    def __init__(self, from_addr=None, to_addr=None, ref_type="DATA"):
        self._from_addr = FakeAddress(from_addr) if from_addr is not None else None
        self._to_addr = FakeAddress(to_addr) if to_addr is not None else None
        self._ref_type = FakeReferenceType(ref_type)

    def getFromAddress(self):
        return self._from_addr

    def getToAddress(self):
        return self._to_addr

    def getReferenceType(self):
        return self._ref_type


class FakeReferenceManager:
    def __init__(self, refs_to=None, refs_from=None):
        self._refs_to = refs_to or {}
        self._refs_from = refs_from or {}

    def getReferencesTo(self, addr):
        return list(self._refs_to.get(str(addr), []))

    def getReferencesFrom(self, addr):
        return list(self._refs_from.get(str(addr), []))


class FakeNamespace:
    def __init__(self, name: str, global_namespace: bool = False):
        self._name = name
        self._global = global_namespace

    def getName(self):
        return self._name

    def isGlobal(self):
        return self._global


class FakeSymbol:
    def __init__(
        self,
        name: str,
        address: str,
        *,
        external_entry_point: bool = False,
        namespace=None,
        symbol_type: str = "LABEL",
    ):
        self._name = name
        self._address = FakeAddress(address)
        self._external_entry_point = external_entry_point
        self._namespace = namespace
        self._symbol_type = symbol_type

    def getName(self):
        return self._name

    def getAddress(self):
        return self._address

    def isExternalEntryPoint(self):
        return self._external_entry_point

    def getParentNamespace(self):
        return self._namespace

    def getSymbolType(self):
        return SimpleNamespace(toString=lambda: self._symbol_type)


class FakeSymbolTable:
    def __init__(self, external_symbols=None, all_symbols=None):
        self._external_symbols = list(external_symbols or [])
        self._all_symbols = list(all_symbols or [])

    def getExternalSymbols(self):
        return list(self._external_symbols)

    def getAllSymbols(self, _forward):
        return list(self._all_symbols)


class FakeDataType:
    def __init__(self, name: str):
        self._name = name

    def getDisplayName(self):
        return self._name


class FakeDataItem:
    def __init__(self, address: str, label: str | None, value_repr: str, data_type="string"):
        self._address = FakeAddress(address)
        self._label = label
        self._value_repr = value_repr
        self._data_type = FakeDataType(data_type)

    def getLabel(self):
        return self._label

    def getDefaultValueRepresentation(self):
        return self._value_repr

    def getAddress(self):
        return self._address

    def getDataType(self):
        return self._data_type

    def getValue(self):
        return self._value_repr


class FakeListing:
    def __init__(self, defined_data=None, data_at=None):
        self._defined_data = list(defined_data or [])
        self._data_at = data_at or {}

    def getDefinedData(self, _forward):
        return list(self._defined_data)

    def getDataAt(self, addr):
        return self._data_at.get(str(addr))


class FakeStringEntry:
    def __init__(self, address: str, value: str):
        self.minAddress = FakeAddress(address)
        self.value = value


class FakeDecompiledFunction:
    def __init__(self, code: str):
        self._code = code

    def getC(self):
        return self._code


class FakeDecompileResults:
    def __init__(self, code: str):
        self._function = FakeDecompiledFunction(code)

    def getDecompiledFunction(self):
        return self._function


class FakeDecompiler:
    def __init__(self, code: str):
        self._code = code

    def decompileFunction(self, _func, _timeout, _monitor):
        return FakeDecompileResults(self._code)


class FakeProgram:
    def __init__(
        self,
        *,
        function_manager=None,
        memory=None,
        symbol_table=None,
        listing=None,
        reference_manager=None,
    ):
        self._function_manager = function_manager
        self._memory = memory
        self._symbol_table = symbol_table
        self._listing = listing
        self._reference_manager = reference_manager

    def getFunctionManager(self):
        return self._function_manager

    def getMemory(self):
        return self._memory

    def getSymbolTable(self):
        return self._symbol_table

    def getListing(self):
        return self._listing

    def getReferenceManager(self):
        return self._reference_manager


class TestBackendSurface(unittest.TestCase):
    def test_backend_surface_is_protocol_agnostic_after_refactor(self):
        self.assertFalse(hasattr(AbstractGhidraClient, "_raw_get"))
        self.assertFalse(hasattr(AbstractGhidraClient, "_raw_post"))
        self.assertFalse(hasattr(AbstractGhidraClient, "safe_get"))
        self.assertFalse(hasattr(AbstractGhidraClient, "safe_post"))

        self.assertTrue(hasattr(GhidraMCPClient, "_http_request_text"))
        self.assertTrue(hasattr(GhidraMCPClient, "_http_get_lines"))
        self.assertTrue(hasattr(GhidraMCPClient, "_http_post_text"))

        py_private_helpers = [
            name
            for name, member in inspect.getmembers(PyGhidraClient, inspect.isfunction)
            if name.startswith("_py_")
        ]
        self.assertEqual(py_private_helpers, [])

        abstract_methods = sorted(
            name
            for name, value in AbstractGhidraClient.__dict__.items()
            if getattr(value, "__isabstractmethod__", False)
        )
        self.assertEqual(GhidraMCPClient.__abstractmethods__, frozenset())
        self.assertEqual(PyGhidraClient.__abstractmethods__, frozenset())

        for name in abstract_methods:
            with self.subTest(method=name):
                self.assertEqual(
                    inspect.signature(getattr(GhidraMCPClient, name)),
                    inspect.signature(getattr(PyGhidraClient, name)),
                )


class TestGhidraMCPRouting(unittest.TestCase):
    def test_get_methods_preserve_http_routing(self):
        cases = [
            ("list_methods", (), {"offset": "1", "limit": "2"}, "methods", {"offset": 1, "limit": 2}, ["line1", "line2"]),
            ("list_classes", (), {"offset": 3, "limit": 4}, "classes", {"offset": 3, "limit": 4}, ["line1", "line2"]),
            ("list_segments", (), {"offset": 0, "limit": 25}, "segments", {"offset": 0, "limit": 20}, ["line1", "line2"]),
            ("list_imports", (), {"offset": 0, "limit": 25}, "imports", {"offset": 0, "limit": 20}, ["line1", "line2"]),
            ("list_exports", (), {"offset": 0, "limit": 25}, "exports", {"offset": 0, "limit": 20}, ["line1", "line2"]),
            ("list_namespaces", (), {"offset": 4, "limit": 5}, "namespaces", {"offset": 4, "limit": 5}, ["line1", "line2"]),
            ("list_data_items", (), {"offset": 0, "limit": 25}, "data", {"offset": 0, "limit": 20}, ["line1", "line2"]),
            ("list_strings", (), {"offset": "2", "limit": "7", "filter": "Error"}, "strings", {"offset": 2, "limit": 7, "filter": "Error"}, ["line1", "line2"]),
            ("search_functions_by_name", ("target",), {"offset": 6, "limit": 7}, "searchFunctions", {"query": "target", "offset": 6, "limit": 7}, ["line1", "line2"]),
            ("get_function_by_address", ("401000",), {}, "get_function_by_address", {"address": "401000"}, "line1\nline2"),
            ("get_current_address", (), {}, "get_current_address", None, "line1\nline2"),
            ("get_current_function", (), {}, "get_current_function", None, "line1\nline2"),
            ("list_functions", (), {"offset": 0, "limit": 20001}, "list_functions", {"offset": 0, "limit": 10000}, ["line1", "line2"]),
            ("decompile_function_by_address", ("401000",), {"offset": 2, "limit": 5}, "decompile_function", {"address": "401000", "offset": 2, "limit": 5}, "line1\nline2"),
            ("disassemble_function", ("401000",), {}, "disassemble_function", {"address": "401000"}, ["line1", "line2"]),
            ("get_xrefs_to", ("0x401000",), {"offset": 1, "limit": 2}, "xrefs_to", {"address": "401000", "offset": 1, "limit": 2}, ["line1", "line2"]),
            ("get_xrefs_from", ("0x401000",), {"offset": 1, "limit": 2}, "xrefs_from", {"address": "401000", "offset": 1, "limit": 2}, ["line1", "line2"]),
            ("get_function_xrefs", ("target_func",), {"offset": 1, "limit": 2}, "function_xrefs", {"name": "target_func", "offset": 1, "limit": 2}, ["line1", "line2"]),
            ("read_bytes", ("0x401000",), {"length": 4, "format": "raw"}, "read_bytes", {"address": "401000", "length": 4, "format": "raw"}, "line1\nline2"),
        ]

        for method_name, args, kwargs, endpoint, expected_params, expected_result in cases:
            with self.subTest(method=method_name):
                client = _make_http_client()
                result = getattr(client, method_name)(*args, **kwargs)

                if expected_params is None:
                    client._http_get_lines.assert_called_once_with(endpoint)  # type: ignore[attr-defined]
                else:
                    client._http_get_lines.assert_called_once_with(endpoint, expected_params)  # type: ignore[attr-defined]
                self.assertEqual(result, expected_result)

    def test_post_methods_preserve_http_routing(self):
        cases = [
            ("decompile_function", ("main",), {"offset": "7", "limit": "9"}, "decompile", "main", {"offset": 7, "limit": 9}),
            ("rename_function", ("old", "new"), {}, "renameFunction", {"oldName": "old", "newName": "new"}, None),
            ("rename_data", ("401000", "label"), {}, "renameData", {"address": "401000", "newName": "label"}, None),
            ("rename_variable", ("func", "old", "new"), {}, "renameVariable", {"functionName": "func", "oldName": "old", "newName": "new"}, None),
            ("set_decompiler_comment", ("401000", "note"), {}, "set_decompiler_comment", {"address": "401000", "comment": "note"}, None),
            ("set_disassembly_comment", ("401000", "note"), {}, "set_disassembly_comment", {"address": "401000", "comment": "note"}, None),
            ("rename_function_by_address", ("401000", "renamed"), {}, "rename_function_by_address", {"function_address": "401000", "new_name": "renamed"}, None),
            ("set_function_prototype", ("401000", "int foo(void)"), {}, "set_function_prototype", {"function_address": "401000", "prototype": "int foo(void)"}, None),
            ("set_local_variable_type", ("401000", "local_10", "char *"), {}, "set_local_variable_type", {"function_address": "401000", "variable_name": "local_10", "new_type": "char *"}, None),
        ]

        for method_name, args, kwargs, endpoint, data, params in cases:
            with self.subTest(method=method_name):
                client = _make_http_client()
                result = getattr(client, method_name)(*args, **kwargs)

                if params is None:
                    client._http_post_text.assert_called_once_with(endpoint, data)  # type: ignore[attr-defined]
                else:
                    client._http_post_text.assert_called_once_with(endpoint, data, params=params)  # type: ignore[attr-defined]
                self.assertEqual(result, "post-ok")

    def test_get_function_xrefs_routes_address_like_inputs_to_xrefs_to(self):
        client = _make_http_client()
        client.get_xrefs_to = MagicMock(return_value=["xref"])  # type: ignore[method-assign]

        result = client.get_function_xrefs("0x401000", offset=5, limit=6)

        client.get_xrefs_to.assert_called_once_with("0x401000", offset=5, limit=6)  # type: ignore[attr-defined]
        self.assertEqual(result, ["xref"])


class TestPyGhidraParity(unittest.TestCase):
    def test_function_listing_tools_emit_http_style_pagination_metadata(self):
        functions = [
            FakeFunction("alpha", "401000"),
            FakeFunction("beta", "401020"),
            FakeFunction("gamma", "401040"),
        ]
        program = FakeProgram(function_manager=FakeFunctionManager(functions))
        client = _make_pyghidra_client(program)

        methods_result = client.list_methods(offset=0, limit=2)
        functions_result = client.list_functions(offset=1, limit=2)

        self.assertEqual(
            methods_result,
            [
                "[Total: 3] [Showing: 1-2] [Next: offset=2, limit=2]",
                "alpha",
                "beta",
            ],
        )
        self.assertEqual(
            functions_result,
            [
                "[Total: 3] [Showing: 2-3]",
                "beta at 401020",
                "gamma at 401040",
            ],
        )

    def test_decompile_tools_emit_http_style_text_metadata(self):
        fake_function = FakeFunction("alpha", "401000")
        client = _make_pyghidra_client(program=object())
        client._find_function_by_name = MagicMock(return_value=fake_function)  # type: ignore[attr-defined]
        client._get_function_for_address = MagicMock(return_value=fake_function)  # type: ignore[attr-defined]
        client._ensure_decompiler = MagicMock(  # type: ignore[attr-defined]
            return_value=FakeDecompiler("line1\nline2\nline3")
        )
        client._address_from_hex = MagicMock(return_value=FakeAddress("401000"))  # type: ignore[attr-defined]

        by_name = client.decompile_function("alpha", offset=0, limit=2)
        by_addr = client.decompile_function_by_address("401000", offset=1, limit=2)

        self.assertEqual(
            by_name,
            "[Total Lines: 3] [Showing Lines: 1-2]\nline1\nline2\n... [Next: offset=2, limit=2]",
        )
        self.assertEqual(
            by_addr,
            "[Total Lines: 3] [Showing Lines: 2-3]\nline2\nline3",
        )

    def test_list_strings_uses_defined_string_iterator_when_available(self):
        class FakeDefinedStringIterator:
            @staticmethod
            def forProgram(_program):
                return [
                    FakeStringEntry("402000", "Error:\nfailed\t!"),
                    FakeStringEntry("402010", "Warning: retry"),
                    FakeStringEntry("402020", "Error: abort"),
                ]

        client = _make_pyghidra_client(program=object())
        client._DefinedStringIterator = FakeDefinedStringIterator

        result = client.list_strings(offset=0, limit=2, filter="Error")

        self.assertEqual(
            result,
            [
                "[Total: 2] [Showing: 1-2]",
                "402000: Error:\nfailed\t!",
                "402020: Error: abort",
            ],
        )

    def test_list_strings_falls_back_to_listing_scan_when_iterator_unavailable(self):
        data_items = [
            FakeDataItem("403000", "hello", "Hello World", data_type="unicode"),
            FakeDataItem("403010", "count", "42", data_type="dword"),
            FakeDataItem("403020", "bye", "Goodbye", data_type="char"),
        ]
        program = FakeProgram(listing=FakeListing(defined_data=data_items))
        client = _make_pyghidra_client(program=program)

        with self.assertLogs("ollama-ghidra-bridge.ghidra", level="ERROR") as logs:
            result = client.list_strings(offset=1, limit=1)

        self.assertEqual(
            result,
            [
                "[Total: 2] [Showing: 2-2]",
                "403020: Goodbye",
            ],
        )
        self.assertTrue(
            any("performance may suffer" in message for message in logs.output)
        )

    def test_list_strings_falls_back_when_defined_string_iterator_raises(self):
        class BrokenDefinedStringIterator:
            @staticmethod
            def forProgram(_program):
                raise RuntimeError("iterator boom")

        data_items = [
            FakeDataItem("404000", "hello", "Fallback Path", data_type="unicode"),
        ]
        program = FakeProgram(listing=FakeListing(defined_data=data_items))
        client = _make_pyghidra_client(program=program)
        client._DefinedStringIterator = BrokenDefinedStringIterator

        with self.assertLogs("ollama-ghidra-bridge.ghidra", level="ERROR") as logs:
            result = client.list_strings(offset=0, limit=5)

        self.assertEqual(
            result,
            [
                "[Total: 1] [Showing: 1-1]",
                "404000: Fallback Path",
            ],
        )
        self.assertFalse(client._use_defined_string_iterator)
        self.assertTrue(
            any("iterator boom" in message for message in logs.output)
        )

    def test_xref_tools_emit_http_style_pagination_metadata(self):
        target_function = FakeFunction("target_func", "401000")
        caller_one = FakeFunction("caller_one", "401100")
        callee_one = FakeFunction("callee_one", "401200")

        ref_mgr = FakeReferenceManager(
            refs_to={
                "401000": [
                    FakeReference(from_addr="401100", ref_type="CALL"),
                    FakeReference(from_addr="401180", ref_type="DATA"),
                ]
            },
            refs_from={
                "401300": [
                    FakeReference(to_addr="401200", ref_type="CALL"),
                    FakeReference(to_addr="404000", ref_type="DATA"),
                ]
            },
        )
        func_mgr = FakeFunctionManager(
            [target_function, caller_one, callee_one],
            containing={
                "401100": caller_one,
                "401180": None,
            },
            at_map={
                "401000": target_function,
                "401200": callee_one,
            },
        )
        listing = FakeListing(
            data_at={
                "404000": FakeDataItem(
                    "404000", "global_data", "1", data_type="dword"
                )
            }
        )
        program = FakeProgram(
            function_manager=func_mgr,
            reference_manager=ref_mgr,
            listing=listing,
            symbol_table=FakeSymbolTable(),
        )

        client = _make_pyghidra_client(program=program)
        client._address_from_hex = MagicMock(side_effect=lambda value: FakeAddress(value))  # type: ignore[attr-defined]
        client._find_function_by_name = MagicMock(return_value=target_function)  # type: ignore[attr-defined]

        xrefs_to = client.get_xrefs_to("0x401000", offset=0, limit=2)
        xrefs_from = client.get_xrefs_from("401300", offset=0, limit=2)
        function_xrefs = client.get_function_xrefs("target_func", offset=0, limit=1)

        self.assertEqual(
            xrefs_to,
            [
                "[Total: 2] [Showing: 1-2]",
                "From 401100 in caller_one [CALL]",
                "From 401180 [DATA]",
            ],
        )
        self.assertEqual(
            xrefs_from,
            [
                "[Total: 2] [Showing: 1-2]",
                "To 401200 to function callee_one [CALL]",
                "To 404000 to data global_data [DATA]",
            ],
        )
        self.assertEqual(
            function_xrefs,
            [
                "[Total: 2] [Showing: 1-1] [Next: offset=1, limit=1]",
                "From 401100 in caller_one [CALL]",
            ],
        )

    def test_misc_listing_tools_emit_http_style_pagination_metadata(self):
        functions = [FakeFunction("search_target", "401000"), FakeFunction("helper", "401020")]
        external_symbols = [FakeSymbol("printf", "500000"), FakeSymbol("puts", "500010")]
        namespace = FakeNamespace("ns1", global_namespace=False)
        all_symbols = [
            FakeSymbol("exported_fn", "401000", external_entry_point=True),
            FakeSymbol("ns_symbol", "401100", namespace=namespace),
        ]
        data_items = [
            FakeDataItem("404000", "item_a", "0x41", data_type="byte"),
            FakeDataItem("404010", None, "0x42", data_type="word"),
        ]
        blocks = [
            FakeMemoryBlock(".text", "401000", "4010ff"),
            FakeMemoryBlock(".rdata", "402000", "4020ff"),
        ]
        ref_mgr = FakeReferenceManager(
            refs_to={
                "500000": [FakeReference(from_addr="401000", ref_type="CALL")],
                "500010": [],
            }
        )
        func_mgr = FakeFunctionManager(functions, containing={"401000": functions[0]})
        program = FakeProgram(
            function_manager=func_mgr,
            memory=FakeMemory(blocks),
            symbol_table=FakeSymbolTable(
                external_symbols=external_symbols,
                all_symbols=all_symbols,
            ),
            listing=FakeListing(defined_data=data_items),
            reference_manager=ref_mgr,
        )
        client = _make_pyghidra_client(program=program)

        self.assertEqual(
            client.list_segments(offset=0, limit=1),
            [
                "[Total: 2] [Showing: 1-1] [Next: offset=1, limit=1]",
                ".text: 401000 - 4010ff",
            ],
        )
        self.assertEqual(
            client.list_imports(offset=0, limit=2),
            [
                "[Total: 2] [Showing: 1-2]",
                "printf -> 500000 [Refs: 1] [Callers: search_target]",
                "puts -> 500010",
            ],
        )
        self.assertEqual(
            client.list_exports(offset=0, limit=1),
            [
                "[Total: 1] [Showing: 1-1]",
                "exported_fn -> 401000",
            ],
        )
        self.assertEqual(
            client.list_namespaces(offset=0, limit=1),
            [
                "[Total: 1] [Showing: 1-1]",
                "ns1",
            ],
        )
        self.assertEqual(
            client.list_data_items(offset=0, limit=2),
            [
                "[Total: 2] [Showing: 1-2]",
                "404000: item_a = 0x41",
                "404010: (unnamed) = 0x42",
            ],
        )
        self.assertEqual(
            client.search_functions_by_name("search", offset=0, limit=1),
            [
                "[Total: 1] [Showing: 1-1]",
                "search_target @ 401000",
            ],
        )

    def test_current_selection_methods_return_explicit_errors(self):
        client = _make_pyghidra_client(program=object())

        current_address = client.get_current_address()
        current_function = client.get_current_function()

        self.assertIn("explicit address", current_address)
        self.assertIn("live Ghidra GUI selection", current_function)
