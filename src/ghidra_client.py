"""
Client for interacting with the GhidraMCP API.
"""

import json
import logging
import time
import re
import struct
import base64
import threading
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import httpx

from src.config import GhidraMCPConfig

logger = logging.getLogger("ollama-ghidra-bridge.ghidra")


class AbstractGhidraClient(ABC):
    """Abstract base class for Ghidra clients.

    Concrete backends (HTTP GhidraMCP server, pyGhidra, etc.) should
    implement the low-level transport hooks and can share higher-level
    tool methods via this interface.
    """

    def __init__(self, config: GhidraMCPConfig, ollama_client=None) -> None:
        self.config = config
        self.ollama_client = ollama_client

    # ------------------------------------------------------------------
    # Low-level transport hooks
    # ------------------------------------------------------------------

    @abstractmethod
    def _raw_get(self, endpoint: str, params: Dict[str, Any] | None = None) -> str:
        """Perform a low-level GET and return raw response text."""

    @abstractmethod
    def _raw_post(self, endpoint: str, data: Dict[str, Any] | str) -> str:
        """Perform a low-level POST and return raw response text."""

    # ------------------------------------------------------------------
    # Shared safe wrappers used by high-level API methods
    # ------------------------------------------------------------------

    def safe_get(
        self, endpoint: str, params: Dict[str, Any] | None = None
    ) -> List[str]:
        """Perform a GET request safely and return the response lines."""
        if params is None:
            params = {}

        try:
            logger.debug(
                f"Sending GET request to GhidraMCP: {endpoint} with params: {params}"
            )
            text = self._raw_get(endpoint, params)
            return text.splitlines()
        except Exception as e:  # pragma: no cover - defensive
            error_msg = f"Request failed: {str(e)}"
            logger.error(error_msg)
            return [error_msg]

    def safe_post(self, endpoint: str, data: Dict[str, Any] | str) -> str:
        """Perform a POST request safely and return the response text."""
        try:
            logger.debug(
                f"Sending POST request to GhidraMCP: {endpoint} with data: {data}"
            )
            return self._raw_post(endpoint, data)
        except Exception as e:  # pragma: no cover - defensive
            error_msg = f"Request failed: {str(e)}"
            logger.error(error_msg)
            return error_msg


class GhidraMCPClient(AbstractGhidraClient):
    """HTTP-based client for interacting with GhidraMCP API."""

    # Safe limit enforcement for bulk operations to prevent context overflow
    MAX_SAFE_LIMIT = 20
    LIMIT_WARNING_TEMPLATE = (
        "⚠️  {method} limit {limit} exceeds MAX_SAFE_LIMIT={max_safe}. "
        "Using targeted searches with 'filter' parameter is recommended. Capping to MAX_SAFE_LIMIT."
    )

    def _coerce_int_param(self, value: Any, *, param_name: str, default: int) -> int:
        """Best-effort conversion for int params crossing the LLM boundary."""
        if value is None:
            return default
        # bool is a subclass of int; treat it as invalid here
        if isinstance(value, bool):
            logger.warning(f"Invalid {param_name}=bool; using default={default}")
            return default
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            s = value.strip()
            try:
                return int(s)
            except ValueError:
                logger.warning(
                    f"Invalid {param_name}='{value}'; using default={default}"
                )
                return default
        logger.warning(
            f"Invalid {param_name} type={type(value).__name__}; using default={default}"
        )
        return default

    def __init__(self, config: GhidraMCPConfig, ollama_client=None):
        """
        Initialize the GhidraMCP client.

        Args:
            config: GhidraMCPConfig object with connection details
            ollama_client: Optional OllamaClient for AI-powered analysis
        """
        super().__init__(config=config, ollama_client=ollama_client)
        self.client = httpx.Client(timeout=config.timeout)
        self.api_version = None

        # Instance management
        self.active_instances = {}  # port -> info_dict
        self.current_instance_port = None

        # Parse default port from config.base_url
        try:
            parsed = urlparse(str(config.base_url))
            if parsed.port:
                self.default_port = parsed.port
                # We'll set this as active initially, but verify it later
                self.current_instance_port = self.default_port
                self.active_instances[self.default_port] = {
                    "url": str(config.base_url).rstrip("/")
                }
            else:
                self.default_port = 8080
                self.current_instance_port = 8080
        except Exception:
            self.default_port = 8080
            self.current_instance_port = 8080

        # Thread-safety: serialize all HTTP requests for future parallel workers
        self._request_lock = threading.Lock()

        logger.info(f"Initialized GhidraMCP client at: {config.base_url}")

        # Try to detect API version and available endpoints
        self._detect_api()

        # Auto-discover other instances on startup
        try:
            self.instances_list()
        except AttributeError:
            # Methods might not be added yet if doing partial update
            pass

    def _detect_api(self):
        """Detect the API version and available endpoints."""
        try:
            # Try to get available methods
            response = self.safe_get("methods", {"offset": 0, "limit": 1})
            # Check if response is valid (list of strings, not error strings)
            if (
                response
                and isinstance(response, list)
                and not (
                    response
                    and (
                        response[0].startswith("Error")
                        or response[0].startswith("Request failed")
                    )
                )
            ):
                logger.info("Successfully connected to GhidraMCP API")
                # Update info for current instance
                if self.current_instance_port:
                    self._update_instance_info(self.current_instance_port)
            else:
                logger.warning(f"Failed to connect to GhidraMCP API: {response}")
        except Exception as e:
            logger.warning(f"Error detecting API: {str(e)}")

    def _get_base_url(self) -> str:
        """Get the base URL for the current active instance."""
        if (
            self.current_instance_port
            and self.current_instance_port in self.active_instances
        ):
            return self.active_instances[self.current_instance_port]["url"]
        return str(self.config.base_url).rstrip("/")

    def _raw_get(self, endpoint: str, params: Dict[str, Any] | None = None) -> str:
        """HTTP implementation of the low-level GET hook.

        Returns the raw response text. Non-200 responses are converted to a
        single-line error string so that :meth:`safe_get` still yields a list
        with an ``"Error ..."`` entry, matching the previous behaviour.
        """
        if params is None:
            params = {}

        base_url = self._get_base_url()
        endpoint = endpoint.lstrip("/")
        url = f"{base_url}/{endpoint}"

        with self._request_lock:
            response = self.client.get(url, params=params, timeout=self.config.timeout)

        response.encoding = "utf-8"
        if response.status_code == 200:
            return response.text
        return f"Error {response.status_code}: {response.text.strip()}"

    def _raw_post(self, endpoint: str, data: Dict[str, Any] | str) -> str:
        """HTTP implementation of the low-level POST hook."""
        base_url = self._get_base_url()
        endpoint = endpoint.lstrip("/")
        url = f"{base_url}/{endpoint}"

        with self._request_lock:
            if isinstance(data, dict):
                response = self.client.post(url, data=data, timeout=self.config.timeout)
            else:
                response = self.client.post(
                    url, data=data.encode("utf-8"), timeout=self.config.timeout
                )

        response.encoding = "utf-8"
        if response.status_code == 200:
            return response.text.strip()
        return f"Error {response.status_code}: {response.text.strip()}"

    def health_check(self) -> bool:
        """
        Check if the GhidraMCP server is available.

        Returns:
            True if the server is available, False otherwise
        """
        try:
            response = self.safe_get("methods", {"offset": 0, "limit": 1})
            return response and not response[0].startswith("Error")
        except Exception as e:
            logger.error(f"GhidraMCP server health check failed: {str(e)}")
            return False

    def check_health(self) -> bool:
        """
        Check if the GhidraMCP server is reachable and responding.

        Returns:
            True if GhidraMCP is healthy, False otherwise
        """
        try:
            # Use the same URL construction pattern as other methods
            base_url = self._get_base_url()
            url = f"{base_url}/methods"

            response = self.client.get(url, params={"offset": 0, "limit": 1})
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"GhidraMCP health check failed: {str(e)}")
            return False

    # Implement GhidraMCP API methods

    def list_methods(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List all function names in the program with pagination.

        Args:
            offset: Offset to start from
            limit: Maximum number of results

        Returns:
            List of function names
        """
        return self.safe_get("methods", {"offset": offset, "limit": limit})

    def list_classes(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List all namespace/class names in the program with pagination.

        Args:
            offset: Offset to start from
            limit: Maximum number of results

        Returns:
            List of class names
        """
        return self.safe_get("classes", {"offset": offset, "limit": limit})

    def decompile_function(self, name: str, offset: int = 0, limit: int = 500) -> str:
        """
        Decompile a specific function by name and return the decompiled C code.

        Args:
            name: Function name
            offset: Line offset (default: 0)
            limit: Max lines to return (default: 500)

        Returns:
            Decompiled C code
        """
        # The new server implementation accepts query params on the same endpoint,
        # but safe_post sends data as body.
        # We need to construct the URL with params manually or modify safe_post.
        # Since safe_post handles URL construction, let's just append params to the endpoint
        # if the server handles them from query string while reading body.
        endpoint = f"decompile?offset={offset}&limit={limit}"
        return self.safe_post(endpoint, name)

    def rename_function(self, old_name: str, new_name: str) -> str:
        """
        Rename a function by its current name to a new user-defined name.

        Args:
            old_name: Current function name
            new_name: New function name

        Returns:
            Result of the rename operation
        """
        return self.safe_post(
            "renameFunction", {"oldName": old_name, "newName": new_name}
        )

    def rename_data(self, address: str, new_name: str) -> str:
        """
        Rename a data label at the specified address.

        Args:
            address: Data address
            new_name: New data name

        Returns:
            Result of the rename operation
        """
        return self.safe_post("renameData", {"address": address, "newName": new_name})

    def list_segments(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List all memory segments in the program with pagination.

        Args:
            offset: Offset to start from
            limit: Maximum number of results

        Returns:
            List of memory segments
        """
        offset = self._coerce_int_param(offset, param_name="offset", default=0)
        limit = self._coerce_int_param(limit, param_name="limit", default=100)

        if limit > self.MAX_SAFE_LIMIT:
            logger.warning(
                self.LIMIT_WARNING_TEMPLATE.format(
                    method="list_segments", limit=limit, max_safe=self.MAX_SAFE_LIMIT
                )
            )
            limit = self.MAX_SAFE_LIMIT
        return self.safe_get("segments", {"offset": offset, "limit": limit})

    def list_imports(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List imported symbols in the program with pagination.

        Args:
            offset: Offset to start from
            limit: Maximum number of results

        Returns:
            List of imported symbols
        """
        offset = self._coerce_int_param(offset, param_name="offset", default=0)
        limit = self._coerce_int_param(limit, param_name="limit", default=100)

        # Enforce safe limit to prevent context overflow
        if limit > self.MAX_SAFE_LIMIT:
            logger.warning(
                self.LIMIT_WARNING_TEMPLATE.format(
                    method="list_imports", limit=limit, max_safe=self.MAX_SAFE_LIMIT
                )
            )
            limit = self.MAX_SAFE_LIMIT

        return self.safe_get("imports", {"offset": offset, "limit": limit})

    def list_exports(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List exported functions/symbols with pagination.

        Args:
            offset: Offset to start from
            limit: Maximum number of results

        Returns:
            List of exported symbols
        """
        offset = self._coerce_int_param(offset, param_name="offset", default=0)
        limit = self._coerce_int_param(limit, param_name="limit", default=100)

        # Enforce safe limit to prevent context overflow
        if limit > self.MAX_SAFE_LIMIT:
            logger.warning(
                self.LIMIT_WARNING_TEMPLATE.format(
                    method="list_exports", limit=limit, max_safe=self.MAX_SAFE_LIMIT
                )
            )
            limit = self.MAX_SAFE_LIMIT

        return self.safe_get("exports", {"offset": offset, "limit": limit})

    def list_namespaces(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List all non-global namespaces in the program with pagination.

        Args:
            offset: Offset to start from
            limit: Maximum number of results

        Returns:
            List of namespaces
        """
        return self.safe_get("namespaces", {"offset": offset, "limit": limit})

    def list_data_items(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List defined data labels and their values with pagination.

        Args:
            offset: Offset to start from
            limit: Maximum number of results

        Returns:
            List of data items
        """
        offset = self._coerce_int_param(offset, param_name="offset", default=0)
        limit = self._coerce_int_param(limit, param_name="limit", default=100)

        if limit > self.MAX_SAFE_LIMIT:
            logger.warning(
                self.LIMIT_WARNING_TEMPLATE.format(
                    method="list_data_items", limit=limit, max_safe=self.MAX_SAFE_LIMIT
                )
            )
            limit = self.MAX_SAFE_LIMIT
        return self.safe_get("data", {"offset": offset, "limit": limit})

    def list_strings(
        self, offset: int = 0, limit: int = 100, filter: str | None = None
    ) -> List[str]:
        """
        List defined strings (or search with substring filter).

        Args:
            offset: Pagination offset
            limit: Maximum number of results
            filter: Optional substring to restrict results (alias: string_search)

        Returns:
            List of strings (raw API response)
        """
        offset = self._coerce_int_param(offset, param_name="offset", default=0)
        limit = self._coerce_int_param(limit, param_name="limit", default=100)

        # Enforce safe limit to prevent context overflow
        # With filter: allow up to 50 (targeted search returns less noise)
        # Without filter: cap to MAX_SAFE_LIMIT (20)
        max_limit = 50 if filter else self.MAX_SAFE_LIMIT
        if limit > max_limit:
            logger.warning(
                self.LIMIT_WARNING_TEMPLATE.format(
                    method="list_strings", limit=limit, max_safe=max_limit
                )
                + (
                    " Consider using 'filter' parameter for targeted searches."
                    if not filter
                    else ""
                )
            )
            limit = max_limit

        params = {"offset": offset, "limit": limit}
        if filter:
            params["filter"] = filter
        return self.safe_get("strings", params)

    def search_functions_by_name(
        self, query: str, offset: int = 0, limit: int = 100
    ) -> List[str]:
        """
        Search for functions whose name contains the given substring.

        Args:
            query: Search query
            offset: Offset to start from
            limit: Maximum number of results

        Returns:
            List of matching functions
        """
        if not query:
            return ["Error: query string is required"]
        return self.safe_get(
            "searchFunctions", {"query": query, "offset": offset, "limit": limit}
        )

    def rename_variable(self, function_name: str, old_name: str, new_name: str) -> str:
        """
        Rename a local variable within a function.

        Args:
            function_name: Function name
            old_name: Current variable name
            new_name: New variable name

        Returns:
            Result of the rename operation
        """
        return self.safe_post(
            "renameVariable",
            {"functionName": function_name, "oldName": old_name, "newName": new_name},
        )

    def get_function_by_address(self, address: str) -> str:
        """
        Get a function by its address.

        Args:
            address: Function address

        Returns:
            Function information
        """
        result = self.safe_get("get_function_by_address", {"address": address})
        return "\n".join(result)

    def get_current_address(self) -> str:
        """
        Get the address currently selected by the user.

        Returns:
            Current address
        """
        result = self.safe_get("get_current_address")
        return "\n".join(result)

    def get_current_function(self) -> str:
        """
        Get the function currently selected by the user.

        Returns:
            Current function
        """
        result = self.safe_get("get_current_function")
        return "\n".join(result)

    def list_functions(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List all functions in the database with pagination.

        Args:
            offset: Offset to start from (default: 0)
            limit: Maximum number of results (default: 100)

        Returns:
            List of functions with pagination metadata
        """
        offset = self._coerce_int_param(offset, param_name="offset", default=0)
        limit = self._coerce_int_param(limit, param_name="limit", default=100)

        # Note: list_functions returns only function names (strings), not full content
        # so we can safely allow larger limits without context overflow risk
        # MAX_SAFE_LIMIT is primarily for operations that return large content
        # Increased limit to support large binaries with 3000+ functions
        MAX_FUNCTIONS_LIMIT = 10000  # Allow pagination up to 10K functions per request
        if limit > MAX_FUNCTIONS_LIMIT:
            logger.warning(
                f"list_functions limit {limit} exceeds MAX_FUNCTIONS_LIMIT={MAX_FUNCTIONS_LIMIT}. Capping to MAX_FUNCTIONS_LIMIT."
            )
            limit = MAX_FUNCTIONS_LIMIT

        return self.safe_get("list_functions", {"offset": offset, "limit": limit})

    def decompile_function_by_address(
        self, address: str, offset: int = 0, limit: int = 500
    ) -> str:
        """
        Decompile a function by address and return the decompiled C code.

        Args:
            address: Function address (e.g., "0x401000")
            offset: Line offset (default: 0)
            limit: Max lines to return (default: 500)

        Returns:
            Decompiled function
        """
        offset = self._coerce_int_param(offset, param_name="offset", default=0)
        limit = self._coerce_int_param(limit, param_name="limit", default=500)

        result = self.safe_get(
            "decompile_function", {"address": address, "offset": offset, "limit": limit}
        )
        return "\n".join(result)

    def analyze_function(self, address: str = None) -> str:
        """
        Analyze a function, including its decompiled code and all functions it calls.
        If no address is provided, uses the current function.

        Args:
            address: Function address (optional)

        Returns:
            Comprehensive function analysis including decompiled code and referenced functions
        """
        if address is None:
            determined_address = None
            # Try with get_current_function() first
            current_function_info = (
                self.get_current_function()
            )  # Expected: "FunctionName @ Address" or error string

            if not current_function_info.startswith("Error"):
                if "@ " in current_function_info:
                    parts = current_function_info.split("@ ", 1)
                    if len(parts) == 2:
                        potential_address = parts[1].strip()
                        # Validate if the extracted address is a non-empty hex string
                        if potential_address and all(
                            c in "0123456789abcdefABCDEF" for c in potential_address
                        ):
                            determined_address = potential_address
                            logger.info(
                                f"analyze_function: Determined address '{determined_address}' from get_current_function() result: '{current_function_info}'."
                            )
                        else:
                            logger.warning(
                                f"analyze_function: Extracted part '{potential_address}' from get_current_function() result ('{current_function_info}') is not a valid hex address."
                            )
                    else:
                        # This case should ideally not be reached if "@ " is present and split is limited to 1
                        logger.warning(
                            f"analyze_function: Unexpected split result from get_current_function() ('{current_function_info}') despite '@ ' being present."
                        )
                else:
                    logger.warning(
                        f"analyze_function: Result from get_current_function() ('{current_function_info}') does not contain '@ '. Attempting get_current_address()."
                    )
            else:
                logger.warning(
                    f"analyze_function: get_current_function() returned an error: '{current_function_info}'. Attempting get_current_address()."
                )

            # If get_current_function() didn't yield a valid address, try get_current_address()
            if determined_address is None:
                logger.info(
                    "analyze_function: Trying get_current_address() as fallback to determine function address."
                )
                current_address_str = (
                    self.get_current_address()
                )  # Expected: "Address" or error string
                # Validate if current_address_str is a non-empty hex string and not an error
                if (
                    not current_address_str.startswith("Error")
                    and current_address_str
                    and all(c in "0123456789abcdefABCDEF" for c in current_address_str)
                ):
                    determined_address = current_address_str
                    logger.info(
                        f"analyze_function: Determined address '{determined_address}' from get_current_address()."
                    )
                else:
                    logger.warning(
                        f"analyze_function: get_current_address() did not yield a valid hex address. Result: '{current_address_str}'"
                    )

            if determined_address:
                address = determined_address
            else:
                logger.error(
                    "analyze_function: Could not determine current function address automatically after trying get_current_function() and get_current_address()."
                )
                return "Error: Could not determine current function address. Please provide an address or ensure a function/address is selected in Ghidra."

        # Get the decompiled code for the target function
        decompiled_code = self.decompile_function_by_address(address)
        if decompiled_code.startswith("Error"):
            return f"Error analyzing function at {address}: {decompiled_code}"

        # Extract function calls from the decompiled code
        function_calls = []
        for line in decompiled_code.splitlines():
            matches = re.finditer(r"\b(\w+)\s*\(", line)
            for match in matches:
                func_name = match.group(1)
                if func_name not in [
                    "if",
                    "while",
                    "for",
                    "switch",
                    "return",
                    "sizeof",
                ]:
                    function_calls.append(func_name)

        function_calls = list(set(function_calls))

        # If AI analysis is available, generate semantic summary
        if self.ollama_client:
            try:
                # Prepare analysis prompt for AI
                analysis_prompt = (
                    f"Analyze this decompiled function and provide a concise summary.\n\n"
                    f"INSTRUCTIONS:\n"
                    f"1. Identify the function's PRIMARY PURPOSE in one sentence\n"
                    f"2. List KEY OPERATIONS it performs\n"
                    f"3. Note any IMPORTANT STRINGS or error messages that reveal its purpose\n"
                    f"4. Identify what PROTOCOL/TECHNOLOGY it relates to (if applicable)\n"
                    f"5. Suggest a DESCRIPTIVE FUNCTION NAME based on its behavior\n\n"
                    f"Format your response as:\n"
                    f"PRIMARY PURPOSE: <one sentence>\n"
                    f"KEY OPERATIONS: <bullet points>\n"
                    f"NOTABLE STRINGS: <relevant strings found in code>\n"
                    f"TECHNOLOGY: <protocol/library/framework if identified>\n"
                    f"SUGGESTED NAME: <descriptive_function_name>\n\n"
                    f"DECOMPILED CODE:\n{decompiled_code[:4000]}\n"  # Limit to avoid context overflow
                )

                ai_summary = self.ollama_client.generate(
                    prompt=analysis_prompt, temperature=0.3
                )

                # Build result with AI analysis first
                result = [
                    f"=== AI-POWERED ANALYSIS OF FUNCTION AT {address} ===",
                    "",
                    ai_summary,
                    "",
                    "=== RAW DECOMPILED CODE (TRUNCATED) ===",
                    "",
                    decompiled_code[:2000],  # Show limited code sample
                    "... [Code truncated for context efficiency] ..."
                    if len(decompiled_code) > 2000
                    else "",
                    "",
                ]

                logger.info(f"AI analysis generated for function at {address}")

            except Exception as e:
                logger.warning(
                    f"AI analysis failed for function at {address}: {e}. Falling back to raw code."
                )
                # Fallback to raw code if AI analysis fails
                result = [
                    f"=== ANALYSIS OF FUNCTION AT {address} ===",
                    "",
                    decompiled_code,
                    "",
                ]
        else:
            # No AI available, use raw code
            result = [
                f"=== ANALYSIS OF FUNCTION AT {address} ===",
                "",
                decompiled_code,
                "",
            ]

        # Optionally append a few key referenced functions (not all to save context)
        if function_calls and len(function_calls) > 0:
            result.append("=== KEY REFERENCED FUNCTIONS (SAMPLE) ===")
            result.append("")
            # Limit to first 3 most interesting functions
            for func_name in list(function_calls)[:3]:
                try:
                    func_code = self.decompile_function(func_name)
                    if not func_code.startswith("Error"):
                        result.append(f"--- Function: {func_name} ---")
                        result.append(func_code[:500])  # Truncate individual functions
                        result.append("...")
                        result.append("")
                except Exception as e:
                    logger.debug(
                        f"Could not decompile referenced function {func_name}: {e}"
                    )

        return "\n".join(result)

    def disassemble_function(self, address: str) -> List[str]:
        """
        Get assembly code (address: instruction; comment) for a function.

        Args:
            address: Function address

        Returns:
            Disassembled function
        """
        return self.safe_get("disassemble_function", {"address": address})

    def set_decompiler_comment(self, address: str, comment: str) -> str:
        """
        Set a comment for a given address in the function pseudocode.

        Args:
            address: Address
            comment: Comment

        Returns:
            Result of the operation
        """
        return self.safe_post(
            "set_decompiler_comment", {"address": address, "comment": comment}
        )

    def set_disassembly_comment(self, address: str, comment: str) -> str:
        """
        Set a comment for a given address in the function disassembly.

        Args:
            address: Address
            comment: Comment

        Returns:
            Result of the operation
        """
        return self.safe_post(
            "set_disassembly_comment", {"address": address, "comment": comment}
        )

    def rename_function_by_address(self, function_address: str, new_name: str) -> str:
        """
        Rename a function by its address.

        Args:
            function_address: Function address
            new_name: New name

        Returns:
            Result of the rename operation
        """
        return self.safe_post(
            "rename_function_by_address",
            {"function_address": function_address, "new_name": new_name},
        )

    def set_function_prototype(self, function_address: str, prototype: str) -> str:
        """
        Set a function's prototype.

        Args:
            function_address: Function address
            prototype: Function prototype

        Returns:
            Result of the operation
        """
        return self.safe_post(
            "set_function_prototype",
            {"function_address": function_address, "prototype": prototype},
        )

    def set_local_variable_type(
        self, function_address: str, variable_name: str, new_type: str
    ) -> str:
        """
        Set a local variable's type.

        Args:
            function_address: Function address
            variable_name: Variable name
            new_type: New type

        Returns:
            Result of the operation
        """
        return self.safe_post(
            "set_local_variable_type",
            {
                "function_address": function_address,
                "variable_name": variable_name,
                "new_type": new_type,
            },
        )

    # ------------------------------------------------------------------
    # 🔄 Address helper & cross-reference endpoints (extended)
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_addr(identifier: str) -> str:
        """Return canonical hexadecimal address **without** any "0x" prefix, lower-cased.

        Accepts typical variants such as:
        • "0x401000"
        • "401000"
        • "FUN_401000" / "thunk_FUN_401000"

        and converts them to "401000" which is the address format required by
        most GhidraMCP endpoints (all lowercase, no prefix).
        """

        if not identifier:
            return ""

        # Fast-path: already looks like an address with no prefix
        if identifier.isalnum() and all(
            c in "0123456789abcdefABCDEF" for c in identifier
        ):
            return identifier.lower()

        # If it starts with 0x/0X remove the prefix
        if identifier.lower().startswith("0x"):
            return identifier[2:].lower()

        # Extract the first long hex substring (6+ chars)
        import re

        m = re.search(r"([0-9a-fA-F]{6,})", identifier)
        if m:
            return m.group(1).lower()

        # Fallback: return as-is (may produce server error, but avoids crash)
        return identifier

    # -- incoming xrefs
    def get_xrefs_to(self, address: str, offset: int = 0, limit: int = 100):
        """List all x-refs *to* `address`. Returns list/str depending on API."""
        norm_addr = self._normalize_addr(address)
        lines = self.safe_get(
            "xrefs_to", {"address": norm_addr, "offset": offset, "limit": limit}
        )
        return lines

    # -- outgoing xrefs
    def get_xrefs_from(self, address: str, offset: int = 0, limit: int = 100):
        """List all x-refs *from* `address`."""
        norm_addr = self._normalize_addr(address)
        lines = self.safe_get(
            "xrefs_from", {"address": norm_addr, "offset": offset, "limit": limit}
        )
        return lines

    # -- name-based helper
    def get_function_xrefs(self, name: str, offset: int = 0, limit: int = 100):
        """List x-refs to a function by `name`. If an address is mistakenly passed,
        we treat it as address form and call get_xrefs_to instead."""
        # Detect address-like input
        if (
            name.upper().startswith("0X")
            or name[:3].upper() == "FUN"
            or name.isalnum()
            and len(name) >= 6
        ):
            addr = self._normalize_addr(name)
            return self.get_xrefs_to(addr, offset=offset, limit=limit)

        lines = self.safe_get(
            "function_xrefs", {"name": name, "offset": offset, "limit": limit}
        )
        return lines

    # ------------------------------------------------------------------
    # Raw byte reading capability
    # ------------------------------------------------------------------

    def read_bytes(self, address: str, length: int = 16, format: str = "hex") -> str:
        """
        Read raw bytes from memory at the specified address.

        Args:
            address: Starting address in hex format (e.g. "0x1400010a0")
            length: Number of bytes to read (1-4096, default: 16)
            format: "hex" for hex dump with ASCII representation,
                    "raw" for base64 encoded bytes

        Returns:
            Hex dump string or base64-encoded raw bytes
        """
        norm_addr = self._normalize_addr(address)
        result = self.safe_get(
            "read_bytes", {"address": norm_addr, "length": length, "format": format}
        )
        return "\n".join(result)

    # =========================================================================
    # Smart Analysis Tools - Algorithmic scanning without LLM intervention
    # =========================================================================

    def scan_function_pointer_tables(
        self,
        min_table_entries: int = 3,
        pointer_size: int = 8,
        max_scan_size: int = 524288,  # 512KB per segment max
        alignment: int = 8,
    ) -> List[Dict]:
        """
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
        """
        results = []

        # Step 1: Get all function addresses and build a lookup table
        logger.info("Building function address lookup table...")
        functions_raw = self.list_functions()
        function_map = {}  # address -> name

        for line in functions_raw:
            # Parse "FUN_140001234 at 140001234" or "main at 140001234"
            if " at " in line:
                parts = line.split(" at ")
                if len(parts) == 2:
                    name = parts[0].strip()
                    addr_str = parts[1].strip()
                    try:
                        addr_int = int(addr_str, 16)
                        function_map[addr_int] = name
                    except ValueError:
                        continue

        if not function_map:
            logger.warning("No functions found, cannot scan for tables")
            return []

        # Determine code address range for quick filtering
        min_func_addr = min(function_map.keys())
        max_func_addr = max(function_map.keys())
        logger.info(
            f"Found {len(function_map)} functions in range 0x{min_func_addr:x} - 0x{max_func_addr:x}"
        )

        # Step 2: Get memory segments and identify data segments
        logger.info("Analyzing memory segments...")
        segments_raw = self.list_segments()
        data_segments = []

        for line in segments_raw:
            # Parse segment info - Ghidra format: ".text: 401000 - 41d5ff"
            # Look for the pattern after the colon: "start - end" where start/end are hex
            seg_match = re.match(
                r"^([^:]+):\s*([0-9a-fA-F]+)\s*-\s*([0-9a-fA-F]+)", line
            )
            if seg_match:
                try:
                    seg_name = seg_match.group(1).strip()
                    start = int(seg_match.group(2), 16)
                    end = int(seg_match.group(3), 16)
                    size = end - start
                    if size > 0:
                        data_segments.append(
                            {"start": start, "end": end, "name": seg_name, "size": size}
                        )
                        logger.debug(
                            f"Parsed segment: {seg_name} 0x{start:x} - 0x{end:x} ({size} bytes)"
                        )
                except ValueError:
                    continue

        # If we couldn't parse segments, try scanning around function addresses
        if not data_segments:
            logger.warning(
                "Could not parse data segments, scanning around function address range"
            )
            # Create a pseudo-segment covering the function address space + some buffer
            data_segments = [
                {
                    "start": max(0, min_func_addr - 0x10000),
                    "end": max_func_addr + 0x10000,
                    "name": "inferred",
                    "size": (max_func_addr - min_func_addr) + 0x20000,
                }
            ]

        # Prioritize data segments where function tables are likely to be found
        # Skip code segments (.text) and special segments
        # Note: .bss is uninitialized data (zeros) so unlikely to have pointers
        skip_segments = {
            ".text",
            ".pdata",
            ".xdata",
            ".rsrc",
            ".buildid",
            "headers",
            ".bss",
            ".reloc",
            ".gnu_debuglink",
            ".comment",
        }
        priority_segments = {".rdata", ".data", ".rodata", ".got", ".got.plt", ".idata"}

        # Sort segments: priority segments first, then others, skip unwanted
        def segment_priority(seg):
            name_lower = seg["name"].lower()
            if name_lower in skip_segments:
                return 2  # Skip these
            if name_lower in priority_segments:
                return 0  # Scan first
            return 1  # Scan after priority

        scannable_segments = [
            s for s in data_segments if s["name"].lower() not in skip_segments
        ]
        scannable_segments.sort(key=segment_priority)

        logger.info(
            f"Scanning {len(scannable_segments)} segment(s) for function pointer tables (skipping code segments)"
        )

        # Step 3: Scan each segment for function pointer sequences
        for segment in scannable_segments:
            scan_size = min(segment["size"], max_scan_size)
            logger.info(
                f"Scanning segment {segment['name']}: 0x{segment['start']:x} ({segment['size']} bytes)"
            )
            tables_in_segment = self._scan_segment_for_tables(
                segment["start"],
                scan_size,
                function_map,
                min_func_addr,
                max_func_addr,
                pointer_size,
                min_table_entries,
                alignment,
            )
            if tables_in_segment:
                logger.info(
                    f"Found {len(tables_in_segment)} table(s) in segment {segment['name']}"
                )
            results.extend(tables_in_segment)

        # Log summary
        if results:
            logger.info(
                f"Total: Found {len(results)} potential function pointer tables"
            )
        else:
            logger.info(
                f"No function pointer tables found (require {min_table_entries}+ consecutive pointers)"
            )
            logger.info(
                "Tip: Some binaries (especially C programs) may not have traditional pointer tables"
            )

        return results

    def _scan_segment_for_tables(
        self,
        start_addr: int,
        scan_length: int,
        function_map: Dict[int, str],
        min_func_addr: int,
        max_func_addr: int,
        pointer_size: int,
        min_table_entries: int,
        alignment: int,
    ) -> List[Dict]:
        """
        Scan a memory region for function pointer tables.

        Returns list of detected tables.
        """
        tables = []
        chunk_size = 4096  # Read 4KB at a time

        for offset in range(0, scan_length, chunk_size):
            read_size = min(chunk_size, scan_length - offset)
            current_addr = start_addr + offset

            try:
                # Read raw bytes (base64 encoded)
                raw_result = self.read_bytes(
                    hex(current_addr), length=read_size, format="raw"
                )

                if (
                    not raw_result
                    or "Error" in raw_result
                    or "No program" in raw_result
                ):
                    continue

                # Decode base64 to bytes
                try:
                    data = base64.b64decode(raw_result.strip())
                    if len(data) < pointer_size:
                        continue
                except Exception:
                    continue

                # Scan for consecutive function pointers
                tables_in_chunk = self._find_pointer_sequences(
                    data,
                    current_addr,
                    function_map,
                    min_func_addr,
                    max_func_addr,
                    pointer_size,
                    min_table_entries,
                    alignment,
                )
                tables.extend(tables_in_chunk)

            except Exception as e:
                logger.debug(f"Error scanning at 0x{current_addr:x}: {e}")
                continue

        return tables

    def _find_pointer_sequences(
        self,
        data: bytes,
        base_addr: int,
        function_map: Dict[int, str],
        min_func_addr: int,
        max_func_addr: int,
        pointer_size: int,
        min_table_entries: int,
        alignment: int,
    ) -> List[Dict]:
        """
        Find sequences of consecutive function pointers in a byte array.
        """
        tables = []

        # Track current sequence
        current_table_start = None
        current_entries = []

        # Format string for struct.unpack (little-endian)
        ptr_format = "<Q" if pointer_size == 8 else "<I"

        i = 0
        while i <= len(data) - pointer_size:
            try:
                # Extract pointer value
                ptr_bytes = data[i : i + pointer_size]
                ptr_value = struct.unpack(ptr_format, ptr_bytes)[0]

                # Quick range check then lookup
                is_valid_func = (
                    min_func_addr <= ptr_value <= max_func_addr
                    and ptr_value in function_map
                )

                if is_valid_func:
                    # We found a valid function pointer
                    if current_table_start is None:
                        current_table_start = base_addr + i

                    current_entries.append(
                        {
                            "offset": len(current_entries) * pointer_size,
                            "pointer": f"0x{ptr_value:x}",
                            "function_name": function_map[ptr_value],
                        }
                    )
                    i += alignment
                    continue

                # Not a valid function pointer - check if we should end current sequence
                if current_entries:
                    if len(current_entries) >= min_table_entries:
                        tables.append(
                            {
                                "table_address": f"0x{current_table_start:x}",
                                "entry_count": len(current_entries),
                                "entries": current_entries.copy(),
                            }
                        )
                    current_table_start = None
                    current_entries = []

                i += alignment

            except struct.error:
                i += alignment
                continue

        # Don't forget the last sequence
        if current_entries and len(current_entries) >= min_table_entries:
            tables.append(
                {
                    "table_address": f"0x{current_table_start:x}",
                    "entry_count": len(current_entries),
                    "entries": current_entries.copy(),
                }
            )

        return tables

    def format_table_scan_results(
        self, tables: List[Dict], max_entries_shown: int = 10
    ) -> str:
        """
        Format the scan results for human-readable output.

        Args:
            tables: List of table dicts from scan_function_pointer_tables
            max_entries_shown: Maximum entries to show per table (default: 10)

        Returns:
            Formatted string with table information
        """
        if not tables:
            return "No function pointer tables detected."

        lines = [f"Found {len(tables)} function pointer table(s):\n"]

        for i, table in enumerate(tables, 1):
            lines.append(
                f"## Table {i}: {table['table_address']} ({table['entry_count']} entries)"
            )

            entries_to_show = table["entries"][:max_entries_shown]
            for entry in entries_to_show:
                lines.append(
                    f"  [{entry['offset']:4d}] {entry['pointer']} -> {entry['function_name']}"
                )

            if len(table["entries"]) > max_entries_shown:
                lines.append(
                    f"  ... and {len(table['entries']) - max_entries_shown} more entries"
                )
            lines.append("")

        return "\n".join(lines)

    # =========================================================================
    # Instance Management
    #
    # Multi-instance discovery and management architecture adapted from:
    # GhydraMCP - https://github.com/starsong/GhydraMCP
    # Authors: starsong and contributors
    #
    # This allows the AI to discover and interact with multiple Ghidra instances
    # simultaneously, each analyzing a different binary on a unique port.
    # =========================================================================

    def instances_list(self) -> str:
        """
        List all active Ghidra instances and auto-discover new ones on localhost.

        Returns:
            Formatted string listing instances and their status
        """
        # Range of ports to scan (standard GhidraMCP ports)
        # Port 8080 is often default, 8192+ are dynamic allocations
        ports_to_scan = [8080, 8081] + list(range(8192, 8200))

        self._discover_instances_internal(ports_to_scan)

        if not self.active_instances:
            return "No active Ghidra instances found. Make sure Ghidra is running with the MCP plugin enabled."

        result = ["=== Active Ghidra Instances ==="]
        for port, info in self.active_instances.items():
            status = "(CURRENT)" if port == self.current_instance_port else ""
            program = info.get("file", "Unknown binary")
            project = info.get("project", "Unknown project")
            result.append(f"• Port {port}: {program} [{project}] {status}")

        result.append("\nUse 'instances_use(port=...)' to switch between instances.")
        return "\n".join(result)

    def instances_discover(
        self, host: str = "localhost", start_port: int = 8192, end_port: int = 8200
    ) -> str:
        """
        Discover Ghidra instances on a specific host and port range.

        Args:
            host: Hostname to scan (default: localhost)
            start_port: Start of port range
            end_port: End of port range

        Returns:
            Discovery results
        """
        ports = list(range(start_port, end_port + 1))
        # Add common default ports if not in range
        if 8080 not in ports:
            ports = [8080] + ports

        self._discover_instances_internal(ports, host=host)
        return self.instances_list()

    def instances_use(self, port: int) -> str:
        """
        Switch the active Ghidra instance to the specified port.

        Args:
            port: The port number of the instance to use

        Returns:
            Confirmation message
        """
        try:
            port = int(port)
        except ValueError:
            return f"Error: Port must be an integer, got '{port}'"

        if port not in self.active_instances:
            # Try to discover it first just in case
            self._discover_instances_internal([port])

        if port in self.active_instances:
            self.current_instance_port = port
            info = self.active_instances[port]

            # Recache info to be sure
            self._update_instance_info(port)
            info = self.active_instances[port]

            return f"Switched to Ghidra instance on port {port} analyzing '{info.get('file', 'unknown')}'"
        else:
            return f"Error: No Ghidra instance found on port {port}. Use 'instances_list' to see available instances."

    def instances_current(self) -> str:
        """
        Get information about the currently active Ghidra instance.

        Returns:
            Instance information
        """
        if (
            not self.current_instance_port
            or self.current_instance_port not in self.active_instances
        ):
            if not self.active_instances:
                return "No active instance selected and no instances found."
            # Fallback to first available if none selected but some exist
            default_port = next(iter(self.active_instances))
            self.current_instance_port = default_port
            return (
                f"No instance explicitly selected. Defaulting to port {default_port}.\n"
                + self.instances_current()
            )

        info = self.active_instances[self.current_instance_port]
        result = [
            f"=== Current Instance: Port {self.current_instance_port} ===",
            f"Binary: {info.get('file', 'Unknown')}",
            f"Project: {info.get('project', 'Unknown')}",
            f"URL: {info.get('url')}",
            f"Plugin Version: {info.get('plugin_version', 'Unknown')}",
        ]
        return "\n".join(result)

    def get_current_program_info(self) -> Dict[str, str]:
        """
        Get structured information about the currently active program.

        Returns:
            Dict containing 'name', 'project', 'port', etc.
        """
        # Ensure we have a valid current instance
        if (
            not self.current_instance_port
            or self.current_instance_port not in self.active_instances
        ):
            if self.active_instances:
                # Auto-select first available if needed
                self.current_instance_port = next(iter(self.active_instances))
            else:
                return {
                    "name": "Unknown Binary",
                    "project": "Unknown",
                    "error": "No active instance",
                }

        # Update info to be fresh
        self._update_instance_info(self.current_instance_port)

        info = self.active_instances.get(self.current_instance_port, {})
        return {
            "name": info.get("file", "Unknown Binary"),
            "project": info.get("project", "Unknown Project"),
            "port": str(self.current_instance_port),
            "url": info.get("url", ""),
            "plugin_version": info.get("plugin_version", "Unknown"),
        }

    def _discover_instances_internal(
        self, ports: List[int], host: str = "localhost"
    ) -> int:
        """Internal helper to scan ports and update active_instances."""
        count = 0

        for port in ports:
            url = f"http://{host}:{port}"
            try:
                # Check plugin version endpoint which is standard in GhidraMCP
                resp = self.client.get(f"{url}/plugin-version", timeout=0.2)
                if resp.status_code == 200:
                    self._update_instance_info(port, url)
                    count += 1
            except Exception:
                continue
        return count

    def _update_instance_info(self, port: int, url: str = None):
        """Update information for a specific instance."""
        if not url:
            # If we don't know the URL, assume localhost if it was default
            if port in self.active_instances:
                url = self.active_instances[port]["url"]
            else:
                url = f"http://localhost:{port}"

        info = {"url": url}

        try:
            # Get program info
            resp = self.client.get(f"{url}/program", timeout=1.0)
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data and isinstance(data["result"], dict):
                    res = data["result"]
                    info["file"] = res.get("name", "Unknown")
                    info["program_id"] = res.get("programId", "")

                    # Parse project from programId if possible
                    pid = res.get("programId", "")
                    if ":" in pid:
                        info["project"] = pid.split(":")[0]

                # Check plugin version too
                ver_resp = self.client.get(f"{url}/plugin-version", timeout=1.0)
                if ver_resp.status_code == 200:
                    ver_data = ver_resp.json()
                    if "result" in ver_data and isinstance(ver_data["result"], dict):
                        info["plugin_version"] = ver_data["result"].get(
                            "plugin_version", "unknown"
                        )
        except Exception:
            pass

        self.active_instances[port] = info


class PyGhidraClient(GhidraMCPClient):
    """pyGhidra-backed implementation of the Ghidra client.

    This reuses the higher-level tool surface from :class:`GhidraMCPClient`
    but replaces the HTTP transport with an in-process pyGhidra integration
    by overriding the low-level ``_raw_get`` / ``_raw_post`` hooks.

    NOTE: This implementation is intentionally conservative and focuses on
    wiring and structure. The exact pyGhidra APIs and project/program
    bootstrap details often vary between environments, so you may need to
    adapt ``_init_pyghidra`` and the endpoint handlers to your setup.
    """

    def __init__(self, config: GhidraMCPConfig, ollama_client=None):
        # Bypass GhidraMCPClient.__init__ (which assumes HTTP) and only
        # initialize the abstract base state.
        AbstractGhidraClient.__init__(self, config=config, ollama_client=ollama_client)

        # Minimal attribute setup so inherited methods that reference these
        # attributes don't explode, even if they are not meaningful for
        # pyGhidra.
        self.api_version = None
        self.active_instances = {}
        self.current_instance_port = None
        self.default_port = None
        self._request_lock = threading.Lock()

        # pyGhidra-specific state
        self._pyghidra = None
        self._project = None
        self._program = None
        self._decomp = None  # Lazy-initialized decompiler interface

        self._init_pyghidra()

    def close(self) -> None:
        """Release pyGhidra project/program resources if possible.

        This is a best-effort cleanup method; failures are logged but do not
        raise. It is safe to call multiple times.
        """
        try:
            if self._decomp is not None:
                try:
                    self._decomp.dispose()
                except Exception:
                    logger.exception("Error disposing pyGhidra decompiler interface")
                finally:
                    self._decomp = None

            # Release program if acquired via consume_program
            if (
                getattr(self, "_program_consumer", None) is not None
                and self._program is not None
            ):
                try:
                    self._program.release(self._program_consumer)
                except Exception:
                    logger.exception("Error releasing pyGhidra program consumer")
                finally:
                    self._program_consumer = None  # type: ignore[attr-defined]

            # Close any program context manager we created
            if getattr(self, "_program_ctx", None) is not None:
                try:
                    self._program_ctx.__exit__(None, None, None)  # type: ignore[call-arg]
                except Exception:
                    logger.exception("Error closing pyGhidra program context")
                finally:
                    self._program_ctx = None  # type: ignore[attr-defined]

            # Close the project context manager if we created one
            if getattr(self, "_project_ctx", None) is not None:
                try:
                    self._project_ctx.__exit__(None, None, None)  # type: ignore[call-arg]
                except Exception:
                    logger.exception("Error closing pyGhidra project context")
                finally:
                    self._project_ctx = None  # type: ignore[attr-defined]

            # Close the open_program() context manager used for binary-only mode.
            if getattr(self, "_open_program_cm", None) is not None:
                try:
                    self._open_program_cm.__exit__(None, None, None)  # type: ignore[call-arg]
                except Exception:
                    logger.exception("Error closing pyGhidra open_program context")
                finally:
                    self._open_program_cm = None  # type: ignore[attr-defined]

            self._program = None
            self._project = None
        except Exception:
            logger.exception("Unexpected error while closing PyGhidraClient")

    # ------------------------------------------------------------------
    # pyGhidra bootstrap
    # ------------------------------------------------------------------

    def _init_pyghidra(self) -> None:
        """Initialize pyGhidra and open the configured project/program.

        This is a best-effort generic bootstrap. Many setups will want to
        customize this logic; it is deliberately simple so it is easy to
        adjust.
        """

        # Ensure GHIDRA_INSTALL_DIR from .env is normalized for this runtime.
        # The main entrypoint already loads .env via python-dotenv, so the
        # value will be in os.environ if configured there. When running on
        # Linux/WSL with a Windows-style path (e.g. "C:\\Program Files\\ghidra"),
        # convert it to a /mnt/c/... path so pyGhidra can find the install.
        import os
        import re

        install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if install_dir and os.name == "posix":
            # Detect simple Windows path pattern like "C:\\..." or "C:/..."
            if re.match(r"^[A-Za-z]:[\\/].*", install_dir):
                drive = install_dir[0].lower()
                rest = install_dir[2:].lstrip("\\/")
                translated = f"/mnt/{drive}/{rest.replace('\\', '/')}"
                logger.info(
                    "Normalized GHIDRA_INSTALL_DIR from '%s' to '%s' for Linux runtime",
                    install_dir,
                    translated,
                )
                install_dir = translated
                os.environ["GHIDRA_INSTALL_DIR"] = translated

        try:
            import pyghidra  # type: ignore[import]
        except ImportError as exc:  # pragma: no cover - environment-specific
            raise RuntimeError(
                "PyGhidra backend selected but the 'pyghidra' package is not installed. "
                "Install it (e.g. 'pip install pyghidra') and ensure Ghidra is configured."
            ) from exc

        # Start the JVM / Ghidra once via pyGhidra. This relies on the
        # GHIDRA_INSTALL_DIR environment variable, which is expected to be set
        # in the project's .env and already loaded into os.environ by
        # python-dotenv at process startup.
        try:  # pragma: no cover - environment-specific
            started_fn = getattr(pyghidra, "started", None)
            start_fn = getattr(pyghidra, "start", None)
            if callable(started_fn) and callable(start_fn):
                if not started_fn():
                    if install_dir:
                        from pathlib import Path

                        start_fn(install_dir=Path(install_dir))
                    else:
                        start_fn()
            elif callable(start_fn):
                # Older/alternate API: best-effort start if not clearly tracked
                if install_dir:
                    from pathlib import Path

                    start_fn(install_dir=Path(install_dir))
                else:
                    start_fn()
        except Exception as exc:
            raise RuntimeError(
                f"Failed to start pyGhidra with GHIDRA_INSTALL_DIR={install_dir!r}: {exc}"
            ) from exc

        # Don't import 'ghidra' here. pyGhidra is responsible for starting the
        # JVM and setting up the classpath when we open a project/program. The
        # various helpers that need Ghidra APIs (e.g. _ensure_decompiler) will
        # import from ghidra.* after that initialization has occurred.

        self._pyghidra = pyghidra

        binary_path = getattr(self.config, "pyghidra_binary", None)
        project_path = getattr(self.config, "pyghidra_project_path", None)
        program_name = getattr(self.config, "pyghidra_program", None)

        # If a binary path is provided and no explicit project is configured,
        # use pyghidra.open_program() to create a new project+program for this
        # binary. The project location defaults to a "pyghidra_projects"
        # directory under the current working directory, or can be overridden
        # via config.ghidra.pyghidra_projects_dir / PYGHIDRA_PROJECTS_DIR.
        if binary_path and not project_path:
            from pathlib import Path
            import os

            bpath = Path(binary_path)
            if not bpath.is_file():
                raise RuntimeError(
                    f"PyGhidraClient: pyghidra_binary '{binary_path}' does not exist or is not a file."
                )

            # Determine base directory for pyGhidra projects
            projects_dir_cfg = getattr(self.config, "pyghidra_projects_dir", None)
            if projects_dir_cfg:
                projects_dir = Path(projects_dir_cfg)
            else:
                projects_dir = Path("pyghidra_projects")

            try:
                projects_dir.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to create pyGhidra projects directory '{projects_dir}': {exc}"
                ) from exc

            project_location = str(projects_dir)
            project_name = bpath.name  # e.g. "vivado.exe"

            try:  # pragma: no cover - environment-specific
                open_prog_cm = self._pyghidra.open_program(
                    str(bpath),
                    project_location=project_location,
                    project_name=project_name,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to open binary '{binary_path}' via pyghidra.open_program: {exc}. "
                    "Please verify the path and that Ghidra/pyGhidra support this binary type."
                ) from exc

            # Keep the context manager alive so the FlatProgramAPI/program
            # remain valid for the lifetime of this client.
            self._open_program_cm = open_prog_cm
            flat_api = open_prog_cm.__enter__()

            try:
                program = flat_api.getCurrentProgram()
            except Exception as exc:
                raise RuntimeError(
                    f"pyghidra.open_program returned an unexpected object: {exc}. "
                    "Expected FlatProgramAPI with getCurrentProgram()."
                ) from exc

            self._program = program

            # Best-effort project discovery for logging; not strictly required
            try:
                domain_file = program.getDomainFile()
                if domain_file is not None:
                    self._project = domain_file.getProject()
                    project_path = str(domain_file.getProject().getProjectLocator())
            except Exception:
                self._project = None

            logger.info(
                "Initialized PyGhidraClient from binary '%s' in project dir '%s'",
                binary_path,
                projects_dir,
            )
            return

        if not project_path:
            raise RuntimeError(
                "PyGhidraClient requires config.ghidra.pyghidra_project_path (or --pyghidra-project) "
                "to be set when backend='pyghidra', or config.ghidra.pyghidra_binary/--pyghidra-binary "
                "to be provided."
            )

        # First open the project. Different pyghidra versions use different
        # signatures for open_project(), so we try the simplest form first and
        # fall back to a (directory, name) variant if needed.
        try:
            try:
                # Common newer signature: open_project(path_or_gpr)
                project_ctx = self._pyghidra.open_project(project_path)
            except TypeError:
                # Some pyghidra builds expect open_project(project_dir, name)
                from pathlib import Path

                p = Path(project_path)
                project_dir = str(p.parent) if str(p.parent) else str(p)
                project_name = p.stem
                project_ctx = self._pyghidra.open_project(project_dir, project_name)

            # Keep the project context manager alive so the project stays
            # open for the lifetime of this client.
            self._project_ctx = project_ctx
            self._project = project_ctx.__enter__()
        except Exception as exc:  # pragma: no cover - environment-specific
            raise RuntimeError(
                f"Failed to open pyGhidra project at '{project_path}': {exc}. "
                "Please adjust PyGhidraClient._init_pyghidra to your environment."
            ) from exc

        # Discover available programs in the project so we can either validate
        # the requested program or auto-select when only one exists. Prefer the
        # modern pyghidra.walk_programs / program_context API when available.

        discovered: List[Tuple[str, str]] = []  # (name, project_path)

        walk_programs = getattr(self._pyghidra, "walk_programs", None)
        program_context = getattr(self._pyghidra, "program_context", None)
        consume_program = getattr(self._pyghidra, "consume_program", None)

        if callable(walk_programs):
            try:

                def _collect(df, prog):
                    try:
                        name = df.getName()
                        path = (
                            df.getPathname()
                        )  # e.g. "/MyProgram" or "/folder/MyProgram"
                        discovered.append((str(name), str(path)))
                    except Exception:
                        return

                walk_programs(self._project, _collect, start="/")
            except Exception:
                discovered = []
        else:
            # Fallback: introspect the project object via the Ghidra API
            try:
                project_data = self._project.getProjectData()
                root = project_data.getRootFolder()
                stack = [root]
                while stack:
                    folder = stack.pop()
                    try:
                        for df in folder.getFiles():
                            try:
                                if hasattr(df, "isProgram") and df.isProgram():
                                    name = df.getName()
                                    path = df.getPathname()
                                    discovered.append((str(name), str(path)))
                            except Exception:
                                continue
                        for sub in folder.getFolders():
                            stack.append(sub)
                    except Exception:
                        continue
            except Exception:
                discovered = []

        # Decide which program to open
        target_program = program_name
        selected_path: Optional[str] = None

        if target_program:
            # If the user provided a project path (starts with "/"), use it
            # directly; otherwise, treat it as a name and try to resolve it.
            if target_program.startswith("/"):
                if discovered and any(path == target_program for _, path in discovered):
                    selected_path = target_program
                else:
                    # Let pyGhidra raise a precise error later if this path
                    # doesn't exist.
                    selected_path = target_program
            else:
                # Match by program name
                for name, path in discovered:
                    if name == target_program:
                        selected_path = path
                        break
                if selected_path is None:
                    pretty = ", ".join(f"{n} ({p})" for n, p in discovered) or "<none>"
                    raise RuntimeError(
                        f"PyGhidra could not find program named '{target_program}' in project. "
                        f"Available programs: {pretty}"
                    )
        else:
            # No explicit program name: attempt auto-selection when exactly
            # one program exists.
            if len(discovered) == 1:
                selected_path = discovered[0][1]
                logger.info(
                    "pyGhidra: auto-selected sole program '%s' at '%s' from project '%s'",
                    discovered[0][0],
                    selected_path,
                    project_path,
                )
            elif len(discovered) > 1:
                pretty = ", ".join(f"{n} ({p})" for n, p in discovered)
                raise RuntimeError(
                    "PyGhidra project contains multiple programs. "
                    "Please specify config.ghidra.pyghidra_program or --pyghidra-program "
                    "as a project path (e.g., '/MyProgram') or name. "
                    f"Available programs: {pretty}"
                )
            else:
                raise RuntimeError(
                    "PyGhidra project appears to contain no programs, or they could not be "
                    "discovered automatically. Please import a program into the project."
                )

        # Open the selected program for long-lived use. Prefer
        # pyghidra.consume_program() so the Program remains valid for the
        # lifetime of this client.
        if not selected_path:
            raise RuntimeError(
                "Internal error: no program path selected for pyGhidra backend."
            )

        try:
            if callable(consume_program):
                # Preferred modern API: keep program alive with explicit
                # consumer; caller is responsible for releasing when done.
                program, consumer = consume_program(self._project, selected_path)
                self._program = program
                self._program_consumer = consumer
            elif callable(program_context):
                # Fallback: keep the context manager alive so the program
                # isn't closed prematurely.
                program_ctx = program_context(self._project, selected_path)
                self._program_ctx = program_ctx
                self._program = program_ctx.__enter__()
            else:
                # Legacy fallback: rely on project.open_program(path)
                if hasattr(self._project, "open_program"):
                    program_ctx = self._project.open_program(selected_path)
                    self._program_ctx = program_ctx
                    self._program = program_ctx.__enter__()
                else:
                    raise RuntimeError(
                        "pyGhidra does not provide consume_program() or program_context(), "
                        "and the project object has no open_program() method."
                    )

        except Exception as exc:  # pragma: no cover - environment-specific
            raise RuntimeError(
                f"Failed to initialize pyGhidra program '{selected_path}' from project "
                f"'{project_path}': {exc}. Please verify the program path/name and that "
                "the project contains this program."
            ) from exc

        logger.info(
            "Initialized PyGhidraClient with project '%s', program '%s'",
            project_path,
            target_program,
        )

    # ------------------------------------------------------------------
    # Health checks (override HTTP-focused defaults)
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Check that the pyGhidra backend is usable.

        For the in-process backend, "healthy" means we have an open Program
        and the decompiler can be initialized successfully.
        """

        if self._program is None:
            logger.error("pyGhidra health_check failed: no program is open")
            return False

        try:
            self._program.getFunctionManager()
            self._ensure_decompiler()
            return True
        except Exception as exc:  # pragma: no cover - environment-specific
            logger.error("pyGhidra health_check failed: %s", exc)
            return False

    def check_health(self) -> bool:
        """UI/tests entry point for health checks.

        Delegate to :meth:`health_check` so both methods share the same
        semantics in the pyGhidra backend.
        """

        return self.health_check()

    def instances_list(self) -> str:
        """Return the single in-process pyGhidra instance description."""
        return self.instances_current()

    def instances_discover(
        self, host: str = "localhost", start_port: int = 8080, end_port: int = 8090
    ) -> str:
        """pyGhidra runs in-process and does not support HTTP instance discovery."""
        return self.instances_current()

    def instances_use(self, port: int) -> str:
        """pyGhidra exposes a single in-process program rather than MCP instances."""
        return (
            "Error: pyGhidra backend does not support switching between HTTP "
            f"instances (requested port {port})."
        )

    def instances_current(self) -> str:
        """Describe the single active pyGhidra program."""
        info = self.get_current_program_info()
        if info.get("error"):
            return info["error"]

        return "\n".join(
            [
                "=== Current Instance: pyGhidra (in-process) ===",
                f"Binary: {info.get('name', 'Unknown Binary')}",
                f"Project: {info.get('project', 'Unknown Project')}",
                f"Program Path: {info.get('program_path', 'Unknown')}",
            ]
        )

    def get_current_program_info(self) -> Dict[str, str]:
        """Return structured information about the currently opened program."""
        if self._program is None:
            return {
                "name": "Unknown Binary",
                "project": "Unknown Project",
                "program_path": "",
                "error": "No pyGhidra program is open",
            }

        info = {
            "name": "Unknown Binary",
            "project": "Unknown Project",
            "program_path": "",
            "backend": "pyghidra",
        }

        try:
            domain_file = self._program.getDomainFile()
            if domain_file is not None:
                try:
                    info["name"] = str(domain_file.getName())
                except Exception:
                    pass
                try:
                    info["program_path"] = str(domain_file.getPathname())
                except Exception:
                    pass
                try:
                    project = domain_file.getProject()
                    if project is not None:
                        info["project"] = str(project.getName())
                except Exception:
                    pass
        except Exception:
            pass

        try:
            if info["name"] == "Unknown Binary":
                info["name"] = str(self._program.getName())
        except Exception:
            pass

        if info["project"] == "Unknown Project":
            try:
                if self._project is not None and hasattr(self._project, "getName"):
                    info["project"] = str(self._project.getName())
            except Exception:
                pass

        return info

    # _init_pyghidra_auto removed: pyGhidra backend now always operates on an
    # explicitly specified project, and either an explicit program name or a
    # single auto-selected program when only one exists.

    # ------------------------------------------------------------------
    # Low-level hooks routed through pyGhidra
    # ------------------------------------------------------------------

    def _raw_get(self, endpoint: str, params: Dict[str, Any] | None = None) -> str:
        """pyGhidra implementation of the low-level GET hook.

        This maps the logical "endpoint" names used by the HTTP backend to
        direct pyGhidra / Ghidra-API calls on the current program.
        """

        if params is None:
            params = {}

        ep = endpoint.lstrip("/")
        ep = ep.split("?", 1)[0]

        # Core enumeration / navigation tools
        if ep in {"methods", "list_functions"}:
            return self._py_list_functions(ep, params)
        if ep == "classes":
            return self._py_list_namespaces(params)
        if ep == "segments":
            return self._py_list_segments(params)
        if ep == "imports":
            return self._py_list_imports(params)
        if ep == "exports":
            return self._py_list_exports(params)
        if ep == "namespaces":
            return self._py_list_namespaces(params)
        if ep == "data":
            return self._py_list_data_items(params)
        if ep == "searchFunctions":
            return self._py_search_functions(params)
        if ep == "strings":
            return self._py_list_strings(params)

        # Decompilation / disassembly
        if ep == "decompile_function":
            # Address-based decompilation
            return self._py_decompile_function_by_address(params)
        if ep == "disassemble_function":
            return self._py_disassemble_function(params)

        # Function / address helpers
        if ep == "get_function_by_address":
            return self._py_get_function_by_address(params)
        if ep == "get_current_address":
            return (
                "Error: get_current_address is unavailable in the pyGhidra backend "
                "because it does not track the live Ghidra GUI cursor. Use an explicit "
                "address instead."
            )
        if ep == "get_current_function":
            return (
                "Error: get_current_function is unavailable in the pyGhidra backend "
                "because it does not track the live Ghidra GUI selection. Use an explicit "
                "function address or name instead."
            )

        # Xref endpoints
        if ep == "xrefs_to":
            return self._py_get_xrefs_to(params)
        if ep == "xrefs_from":
            return self._py_get_xrefs_from(params)
        if ep == "function_xrefs":
            return self._py_get_function_xrefs(params)

        # Bytes
        if ep == "read_bytes":
            return self._py_read_bytes(params)

        # Fallback for unimplemented endpoints
        return f"Error: endpoint '{ep}' is not yet implemented for pyGhidra backend"

    def _raw_post(self, endpoint: str, data: Dict[str, Any] | str) -> str:
        """pyGhidra implementation of the low-level POST hook.

        This handles mutation-style operations (renames, comments, prototypes,
        etc.) by directly manipulating the current Ghidra program via
        pyGhidra APIs.
        """

        ep_full = endpoint.lstrip("/")
        ep, _, qs = ep_full.partition("?")

        # Decompile by function name (used by decompile_function(name))
        if ep == "decompile" and isinstance(data, str):
            query_params = {
                key: values[-1]
                for key, values in parse_qs(qs, keep_blank_values=False).items()
                if values
            }
            return self._py_decompile_function_by_name(data, query_params)

        if not isinstance(data, dict):
            return f"Error: endpoint '{ep}' expects JSON object payload in pyGhidra backend"

        # Rename operations
        if ep == "renameFunction":
            return self._py_rename_function(data)
        if ep == "renameData":
            return self._py_rename_data(data)
        if ep == "renameVariable":
            return self._py_rename_variable(data)
        if ep == "rename_function_by_address":
            return self._py_rename_function_by_address(data)

        # Comments
        if ep == "set_decompiler_comment":
            return self._py_set_decompiler_comment(data)
        if ep == "set_disassembly_comment":
            return self._py_set_disassembly_comment(data)

        # Prototypes and variable types
        if ep == "set_function_prototype":
            return self._py_set_function_prototype(data)
        if ep == "set_local_variable_type":
            return self._py_set_local_variable_type(data)

        return f"Error: endpoint '{ep}' is not implemented for pyGhidra backend"

    # ------------------------------------------------------------------
    # Internal helpers for pyGhidra-backed queries
    # ------------------------------------------------------------------

    # -- generic helpers -------------------------------------------------

    def _py_addr_from_hex(self, addr_str: str):
        """Convert a hex string (with or without 0x) to a Ghidra Address."""
        if self._program is None:
            raise RuntimeError("pyGhidra program is not initialized")

        af = self._program.getAddressFactory()
        s = addr_str.strip()
        if s.lower().startswith("0x"):
            s = s[2:]
        # Use default address space for now
        space = af.getDefaultAddressSpace()
        return space.getAddress(int(s, 16))

    def _py_get_offset_limit(
        self, params: Dict[str, Any], *, default_limit: int = 100
    ) -> Tuple[int, int]:
        """Parse and clamp offset/limit parameters consistently."""
        offset = max(
            0,
            self._coerce_int_param(
                params.get("offset"), param_name="offset", default=0
            ),
        )
        limit = max(
            0,
            self._coerce_int_param(
                params.get("limit"), param_name="limit", default=default_limit
            ),
        )
        return offset, limit

    @staticmethod
    def _py_paginate_lines(lines: List[str], offset: int, limit: int) -> List[str]:
        """Slice a list of rendered lines using MCP-style pagination."""
        if limit == 0:
            return []
        return lines[offset : offset + limit]

    def _py_paginate_text(
        self, text: str, params: Dict[str, Any], *, default_limit: int = 500
    ) -> str:
        """Apply line-based pagination to a multi-line text payload."""
        offset, limit = self._py_get_offset_limit(params, default_limit=default_limit)
        return "\n".join(self._py_paginate_lines(text.splitlines(), offset, limit))

    def _py_get_function_for_address(self, addr):
        """Return the function at or containing the given address."""
        if self._program is None:
            raise RuntimeError("pyGhidra program is not initialized")

        func_mgr = self._program.getFunctionManager()
        func = func_mgr.getFunctionAt(addr)
        if func is None:
            func = func_mgr.getFunctionContaining(addr)
        return func

    def _py_find_function_by_name(self, name: str):
        """Best-effort lookup of a Function by name.

        PyGhidra's FunctionManager in some environments does not provide an
        overload of getFunction(str), so we resolve by querying the symbol
        table for FUNCTION symbols and then mapping those to Functions.
        """
        if self._program is None:
            raise RuntimeError("pyGhidra program is not initialized")

        func_mgr = self._program.getFunctionManager()
        st = self._program.getSymbolTable()

        # First try symbol-based resolution
        syms = st.getSymbols(name, None)
        for sym in syms:
            try:
                if sym.getSymbolType().toString() == "FUNCTION":
                    func = func_mgr.getFunctionAt(sym.getAddress())
                    if func is not None:
                        return func
            except Exception:
                continue

        # Fallback: scan all functions and match by name (handles cases where
        # function names are not exposed as symbols, or when the symbol table
        # lookup behaves differently across Ghidra versions).
        try:
            funcs_iter = func_mgr.getFunctions(True)
            for f in funcs_iter:
                try:
                    if str(f.getName()) == name:
                        return f
                except Exception:
                    continue
        except Exception:
            pass

        # Final fallback: if the name contains an address-like hex substring,
        # attempt to resolve by address.
        import re

        m = re.search(r"([0-9a-fA-F]{6,})", name)
        if m:
            try:
                addr = self._py_addr_from_hex(m.group(1))
                func = func_mgr.getFunctionAt(addr)
                if func is not None:
                    return func
            except Exception:
                pass

        return None

    def _ensure_decompiler(self):
        """Lazily initialize the Ghidra decompiler interface."""
        if self._decomp is not None:
            return self._decomp
        if self._program is None:
            raise RuntimeError("pyGhidra program is not initialized")

        try:
            from ghidra.app.decompiler import DecompInterface  # type: ignore[import]
            from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]
        except ImportError as exc:  # pragma: no cover - environment-specific
            raise RuntimeError(
                "Ghidra decompiler classes not available in pyGhidra environment"
            ) from exc

        decomp = DecompInterface()
        decomp.openProgram(self._program)
        # Store monitor on instance so we can reuse it
        self._decomp_monitor = ConsoleTaskMonitor()
        self._decomp = decomp
        return decomp

    # -- list / enumeration endpoints -----------------------------------

    def _py_list_functions(self, endpoint: str, params: Dict[str, Any]) -> str:
        """Return a newline-separated list of function names via pyGhidra.

        This deliberately keeps the format simple: one function name per
        line. Callers that rely on address parsing from names may see
        different behaviour compared to the HTTP backend and should be
        updated if necessary.
        """

        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        offset, limit = self._py_get_offset_limit(params)

        try:
            func_mgr = self._program.getFunctionManager()
            funcs_iter = func_mgr.getFunctions(True)

            lines: List[str] = []
            for f in funcs_iter:
                try:
                    name = str(f.getName())
                    if endpoint == "list_functions":
                        # Match HTTP format: "NAME at ADDRESS"
                        entry = f.getEntryPoint()
                        addr_hex = (
                            f"{entry.getOffset():x}" if entry is not None else "0"
                        )
                        lines.append(f"{name} at {addr_hex}")
                    else:
                        # "methods" just returns names
                        lines.append(name)
                except Exception:
                    continue

            return "\n".join(self._py_paginate_lines(lines, offset, limit))
        except Exception as exc:  # pragma: no cover - environment-specific
            logger.error("pyGhidra list_functions failed: %s", exc)
            return f"Error: pyGhidra list_functions failed: {exc}"

    def _py_list_namespaces(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        offset, limit = self._py_get_offset_limit(params)

        try:
            st = self._program.getSymbolTable()
            it = st.getAllSymbols(True)
            names = set()
            for sym in it:
                try:
                    stype = sym.getSymbolType().toString()
                    if stype == "NAMESPACE":
                        names.add(sym.getName(True))
                except Exception:
                    continue

            sorted_names = sorted(names)
            return "\n".join(self._py_paginate_lines(sorted_names, offset, limit))
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra list_namespaces failed: %s", exc)
            return f"Error: pyGhidra list_namespaces failed: {exc}"

    def _py_list_segments(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        offset, limit = self._py_get_offset_limit(params)

        try:
            mem = self._program.getMemory()
            blocks = mem.getBlocks()
            lines: List[str] = []
            for blk in blocks:
                try:
                    name = blk.getName()
                    start = blk.getStart().getOffset()
                    end = blk.getEnd().getOffset()
                    lines.append(f"{name}: {start:x} - {end:x}")
                except Exception:
                    continue
            return "\n".join(self._py_paginate_lines(lines, offset, limit))
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra list_segments failed: %s", exc)
            return f"Error: pyGhidra list_segments failed: {exc}"

    def _py_list_imports(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        offset, limit = self._py_get_offset_limit(params)

        try:
            st = self._program.getSymbolTable()
            ref_mgr = self._program.getReferenceManager()
            func_mgr = self._program.getFunctionManager()
            it = st.getExternalSymbols()
            lines = []
            for sym in it:
                try:
                    line = f"{sym.getName(True)} -> {sym.getAddress()}"
                    callers: List[str] = []
                    ref_count = 0
                    for ref in ref_mgr.getReferencesTo(sym.getAddress()):
                        ref_count += 1
                        if ref_count <= 5:
                            from_addr = ref.getFromAddress()
                            caller = func_mgr.getFunctionContaining(from_addr)
                            callers.append(
                                caller.getName() if caller is not None else str(from_addr)
                            )

                    if ref_count > 0:
                        line += f" [Refs: {ref_count}]"
                        if callers:
                            line += f" [Callers: {', '.join(callers)}"
                            if ref_count > 5:
                                line += ", ..."
                            line += "]"

                    lines.append(line)
                except Exception:
                    continue
            return "\n".join(self._py_paginate_lines(lines, offset, limit))
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra list_imports failed: %s", exc)
            return f"Error: pyGhidra list_imports failed: {exc}"

    def _py_list_exports(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        offset, limit = self._py_get_offset_limit(params)

        try:
            st = self._program.getSymbolTable()
            symbols = []
            for sym in st.getAllSymbols(True):
                symbols.append(sym)
            lines = []
            for sym in symbols:
                try:
                    if hasattr(sym, "isExternalEntryPoint") and sym.isExternalEntryPoint():
                        lines.append(f"{sym.getName(True)} -> {sym.getAddress()}")
                except Exception:
                    continue

            # Fallback for environments where isExternalEntryPoint() is not available.
            if not lines:
                for sym in symbols:
                    try:
                        stype = sym.getSymbolType().toString()
                        if stype == "FUNCTION" and sym.isExternal() is False:
                            lines.append(f"{sym.getName(True)} -> {sym.getAddress()}")
                    except Exception:
                        continue

            return "\n".join(self._py_paginate_lines(lines, offset, limit))
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra list_exports failed: %s", exc)
            return f"Error: pyGhidra list_exports failed: {exc}"

    def _py_list_data_items(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        offset, limit = self._py_get_offset_limit(params)

        try:
            listing = self._program.getListing()
            data_iter = listing.getDefinedData(True)
            lines: List[str] = []
            for d in data_iter:
                try:
                    label = d.getLabel() if hasattr(d, "getLabel") else None
                    value_repr = (
                        d.getDefaultValueRepresentation()
                        if hasattr(d, "getDefaultValueRepresentation")
                        else str(d.getValue())
                    )
                    line = f"{d.getAddress()}: {label or '(unnamed)'} = {value_repr}"
                    lines.append(line)
                except Exception:
                    continue
            return "\n".join(self._py_paginate_lines(lines, offset, limit))
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra list_data_items failed: %s", exc)
            return f"Error: pyGhidra list_data_items failed: {exc}"

    def _py_list_strings(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        offset = int(params.get("offset", 0) or 0)
        limit = int(params.get("limit", 100) or 100)
        filter_text = params.get("filter") or ""

        try:
            listing = self._program.getListing()
            data_iter = listing.getDefinedData(True)
            strings = []
            for d in data_iter:
                try:
                    dt = d.getDataType()
                    dt_name = dt.getDisplayName().lower()
                    if "string" in dt_name or "unicode" in dt_name:
                        s = str(d.getValue())
                        if filter_text and filter_text not in s:
                            continue
                        addr = d.getAddress().getOffset()
                        strings.append(f"{addr:x}: {s}")
                except Exception:
                    continue

            sliced = strings[offset : offset + limit]
            return "\n".join(sliced)
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra list_strings failed: %s", exc)
            return f"Error: pyGhidra list_strings failed: {exc}"

    # -- search / xrefs / bytes -----------------------------------------

    def _py_search_functions(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        query = params.get("query") or ""
        offset, limit = self._py_get_offset_limit(params)

        if not query:
            return "Error: query string is required"

        try:
            func_mgr = self._program.getFunctionManager()
            funcs_iter = func_mgr.getFunctions(True)
            matches: List[str] = []
            for f in funcs_iter:
                try:
                    name = str(f.getName())
                    if query.lower() in name.lower():
                        matches.append(f"{name} @ {f.getEntryPoint()}")
                except Exception:
                    continue

            if not matches:
                return f"No functions matching '{query}'"

            return "\n".join(self._py_paginate_lines(matches, offset, limit))
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra search_functions failed: %s", exc)
            return f"Error: pyGhidra search_functions failed: {exc}"

    def _py_decompile_function_by_address(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        addr_str = params.get("address")
        if not addr_str:
            return "Error: 'address' parameter is required for decompile_function"

        try:
            addr = self._py_addr_from_hex(str(addr_str))
            func = self._py_get_function_for_address(addr)
            if func is None:
                return f"Error: No function found at or containing address {addr_str}"

            decomp = self._ensure_decompiler()
            results = decomp.decompileFunction(func, 60, self._decomp_monitor)
            df = results.getDecompiledFunction()
            if df is None:
                return f"Error: Decompilation failed for {addr_str}"
            return self._py_paginate_text(df.getC(), params, default_limit=500)
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra decompile_function failed: %s", exc)
            return f"Error: pyGhidra decompile_function failed: {exc}"

    def _py_decompile_function_by_name(
        self, name: str, params: Dict[str, Any] | None = None
    ) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        if params is None:
            params = {}

        try:
            func = self._py_find_function_by_name(name)
            if func is None:
                return f"Error: function '{name}' not found"

            decomp = self._ensure_decompiler()
            results = decomp.decompileFunction(func, 60, self._decomp_monitor)
            df = results.getDecompiledFunction()
            if df is None:
                return f"Error: Decompilation failed for function '{name}'"
            return self._py_paginate_text(df.getC(), params, default_limit=500)
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra decompile_function(name) failed: %s", exc)
            return f"Error: pyGhidra decompile_function(name) failed: {exc}"

    def _py_get_function_by_address(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        addr_str = params.get("address")
        if not addr_str:
            return "Error: 'address' parameter is required for get_function_by_address"

        try:
            addr = self._py_addr_from_hex(str(addr_str))
            func = self._py_get_function_for_address(addr)
            if func is None:
                return f"Error: No function found at or containing address {addr_str}"

            entry = func.getEntryPoint()
            return (
                f"Function: {func.getName()} at {entry}\n"
                f"Signature: {func.getSignature()}\n"
                f"Entry: {entry}\n"
                f"Body: {func.getBody().getMinAddress()} - {func.getBody().getMaxAddress()}"
            )
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra get_function_by_address failed: %s", exc)
            return f"Error: pyGhidra get_function_by_address failed: {exc}"

    def _py_disassemble_function(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        addr_str = params.get("address")
        if not addr_str:
            return "Error: 'address' parameter is required for disassemble_function"

        try:
            addr = self._py_addr_from_hex(str(addr_str))
            func = self._py_get_function_for_address(addr)
            if func is None:
                return f"Error: No function found at or containing address {addr_str}"

            listing = self._program.getListing()
            body = func.getBody()
            code_units = listing.getCodeUnits(body, True)
            lines: List[str] = []
            for cu in code_units:
                try:
                    comment = listing.getComment(cu.EOL_COMMENT, cu.getAddress())
                    comment_suffix = f" ; {comment}" if comment else ""
                    instr = cu.toString()
                    lines.append(f"{cu.getAddress()}: {instr}{comment_suffix}")
                except Exception:
                    continue
            return "\n".join(lines)
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra disassemble_function failed: %s", exc)
            return f"Error: pyGhidra disassemble_function failed: {exc}"

    def _py_get_xrefs_to(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        addr_str = params.get("address")
        if not addr_str:
            return "Error: 'address' parameter is required for xrefs_to"

        try:
            addr = self._py_addr_from_hex(str(addr_str))
            ref_mgr = self._program.getReferenceManager()
            func_mgr = self._program.getFunctionManager()
            refs = ref_mgr.getReferencesTo(addr)
            lines = []
            for r in refs:
                try:
                    from_addr = r.getFromAddress()
                    ref_type = r.getReferenceType().toString()
                    from_func = func_mgr.getFunctionContaining(from_addr)
                    func_info = f" in {from_func.getName()}" if from_func else ""
                    lines.append(f"From {from_addr}{func_info} [{ref_type}]")
                except Exception:
                    continue
            offset, limit = self._py_get_offset_limit(params)
            return "\n".join(self._py_paginate_lines(lines, offset, limit))
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra get_xrefs_to failed: %s", exc)
            return f"Error: pyGhidra get_xrefs_to failed: {exc}"

    def _py_get_xrefs_from(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        addr_str = params.get("address")
        if not addr_str:
            return "Error: 'address' parameter is required for xrefs_from"

        try:
            addr = self._py_addr_from_hex(str(addr_str))
            ref_mgr = self._program.getReferenceManager()
            func_mgr = self._program.getFunctionManager()
            listing = self._program.getListing()
            refs = ref_mgr.getReferencesFrom(addr)
            lines = []
            for r in refs:
                try:
                    to_addr = r.getToAddress()
                    ref_type = r.getReferenceType().toString()
                    target_info = ""
                    to_func = func_mgr.getFunctionAt(to_addr)
                    if to_func is not None:
                        target_info = f" to function {to_func.getName()}"
                    else:
                        data = listing.getDataAt(to_addr)
                        if data is not None:
                            label = data.getLabel() or getattr(data, "getPathName", lambda: "")()
                            target_info = f" to data {label}"
                    lines.append(f"To {to_addr}{target_info} [{ref_type}]")
                except Exception:
                    continue
            offset, limit = self._py_get_offset_limit(params)
            return "\n".join(self._py_paginate_lines(lines, offset, limit))
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra get_xrefs_from failed: %s", exc)
            return f"Error: pyGhidra get_xrefs_from failed: {exc}"

    def _py_get_function_xrefs(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        name = params.get("name")
        if not name:
            return "Error: 'name' parameter is required for function_xrefs"

        try:
            symbol_table = self._program.getSymbolTable()
            ref_mgr = self._program.getReferenceManager()
            func_mgr = self._program.getFunctionManager()

            target_address = None
            target_type = "function"

            func = self._py_find_function_by_name(name)
            if func is not None:
                target_address = func.getEntryPoint()

            if target_address is None:
                for sym in symbol_table.getExternalSymbols():
                    try:
                        if sym.getName() == name:
                            target_address = sym.getAddress()
                            target_type = "external"
                            break
                    except Exception:
                        continue

            if target_address is None:
                try:
                    syms = symbol_table.getSymbols(name, None)
                except TypeError:
                    syms = symbol_table.getSymbols(name)
                for sym in syms:
                    try:
                        target_address = sym.getAddress()
                        target_type = sym.getSymbolType().toString().lower()
                        break
                    except Exception:
                        continue

            if target_address is None:
                return f"Error: function or symbol '{name}' not found"

            lines = []
            for r in ref_mgr.getReferencesTo(target_address):
                try:
                    from_addr = r.getFromAddress()
                    ref_type = r.getReferenceType().toString()
                    from_func = func_mgr.getFunctionContaining(from_addr)
                    func_info = f" in {from_func.getName()}" if from_func else ""
                    lines.append(f"From {from_addr}{func_info} [{ref_type}]")
                except Exception:
                    continue

            if not lines:
                return (
                    f"No references found to {target_type}: {name} "
                    f"(at {target_address})"
                )

            offset, limit = self._py_get_offset_limit(params)
            return "\n".join(self._py_paginate_lines(lines, offset, limit))
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra get_function_xrefs failed: %s", exc)
            return f"Error: pyGhidra get_function_xrefs failed: {exc}"

    def _py_read_bytes(self, params: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        addr_str = params.get("address")
        if not addr_str:
            return "Error: 'address' parameter is required for read_bytes"

        length = int(params.get("length", 16) or 16)
        fmt = (params.get("format") or "hex").lower()

        try:
            addr = self._py_addr_from_hex(str(addr_str))
            mem = self._program.getMemory()
            b = bytearray(length)
            mem.getBytes(addr, b)

            if fmt == "raw":
                # Base64-encode raw bytes (matching HTTP backend semantics)
                return base64.b64encode(bytes(b)).decode("ascii")

            # Default: hex dump with ASCII
            hex_pairs = [f"{x:02x}" for x in b]
            ascii_repr = "".join(chr(x) if 32 <= x < 127 else "." for x in b)
            return f"{' '.join(hex_pairs)}  |{ascii_repr}|"
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra read_bytes failed: %s", exc)
            return f"Error: pyGhidra read_bytes failed: {exc}"

    # -- mutation helpers ------------------------------------------------

    def _py_rename_function(self, data: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        old_name = data.get("oldName")
        new_name = data.get("newName")
        if not old_name or not new_name:
            return "Error: 'oldName' and 'newName' are required for renameFunction"

        try:
            from ghidra.program.model.symbol import SourceType  # type: ignore[import]

            st = self._program.getSymbolTable()
            func_mgr = self._program.getFunctionManager()
            syms = st.getSymbols(old_name, None)
            target_func = None
            for sym in syms:
                try:
                    if sym.getSymbolType().toString() == "FUNCTION":
                        target_func = func_mgr.getFunctionAt(sym.getAddress())
                        break
                except Exception:
                    continue

            if target_func is None:
                return f"Error: function '{old_name}' not found"

            desc = f"rename_function: {old_name} -> {new_name}"
            tx = getattr(self._pyghidra, "transaction", None)
            tm_fn = getattr(self._pyghidra, "task_monitor", None)

            if callable(tx):
                monitor = tm_fn() if callable(tm_fn) else None
                with tx(self._program, desc):
                    target_func.setName(new_name, SourceType.USER_DEFINED)
                # Best-effort save; ignore failures silently
                try:
                    if monitor is not None:
                        self._program.save(desc, monitor)
                except Exception:
                    pass
            else:
                target_func.setName(new_name, SourceType.USER_DEFINED)

            return f"Renamed function '{old_name}' to '{new_name}'"
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra renameFunction failed: %s", exc)
            return f"Error: pyGhidra renameFunction failed: {exc}"

    def _py_rename_function_by_address(self, data: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        addr_str = data.get("function_address")
        new_name = data.get("new_name")
        if not addr_str or not new_name:
            return "Error: 'function_address' and 'new_name' are required for rename_function_by_address"

        try:
            from ghidra.program.model.symbol import SourceType  # type: ignore[import]

            addr = self._py_addr_from_hex(str(addr_str))
            func = self._py_get_function_for_address(addr)
            if func is None:
                return f"Error: No function found at or containing address {addr_str}"

            desc = f"rename_function_by_address: {addr_str} -> {new_name}"
            tx = getattr(self._pyghidra, "transaction", None)
            tm_fn = getattr(self._pyghidra, "task_monitor", None)

            if callable(tx):
                monitor = tm_fn() if callable(tm_fn) else None
                with tx(self._program, desc):
                    func.setName(new_name, SourceType.USER_DEFINED)
                try:
                    if monitor is not None:
                        self._program.save(desc, monitor)
                except Exception:
                    pass
            else:
                func.setName(new_name, SourceType.USER_DEFINED)

            return f"Renamed function at {addr_str} to '{new_name}'"
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra rename_function_by_address failed: %s", exc)
            return f"Error: pyGhidra rename_function_by_address failed: {exc}"

    def _py_rename_data(self, data: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        addr_str = data.get("address")
        new_name = data.get("newName")
        if not addr_str or not new_name:
            return "Error: 'address' and 'newName' are required for renameData"

        try:
            from ghidra.program.model.symbol import SourceType  # type: ignore[import]

            addr = self._py_addr_from_hex(str(addr_str))
            st = self._program.getSymbolTable()

            desc = f"rename_data: {addr_str} -> {new_name}"
            tx = getattr(self._pyghidra, "transaction", None)
            tm_fn = getattr(self._pyghidra, "task_monitor", None)

            if callable(tx):
                monitor = tm_fn() if callable(tm_fn) else None
                with tx(self._program, desc):
                    sym = st.getPrimarySymbol(addr)
                    if sym is not None:
                        sym.setName(new_name, SourceType.USER_DEFINED)
                    else:
                        st.createLabel(addr, new_name, None, SourceType.USER_DEFINED)
                try:
                    if monitor is not None:
                        self._program.save(desc, monitor)
                except Exception:
                    pass
            else:
                sym = st.getPrimarySymbol(addr)
                if sym is not None:
                    sym.setName(new_name, SourceType.USER_DEFINED)
                else:
                    st.createLabel(addr, new_name, None, SourceType.USER_DEFINED)

            return f"Renamed data at {addr_str} to '{new_name}'"
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra renameData failed: %s", exc)
            return f"Error: pyGhidra renameData failed: {exc}"

    def _py_rename_variable(self, data: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        func_name = data.get("functionName")
        old_name = data.get("oldName")
        new_name = data.get("newName")
        if not func_name or not old_name or not new_name:
            return "Error: 'functionName', 'oldName', and 'newName' are required for renameVariable"

        try:
            from ghidra.program.model.symbol import SourceType  # type: ignore[import]

            func = self._py_find_function_by_name(func_name)
            if func is None:
                return f"Error: function '{func_name}' not found"

            try:
                vars_iter = func.getAllVariables()
            except Exception:
                # Fallback: combine parameters and locals
                vars_iter = list(func.getParameters()) + list(func.getLocalVariables())

            target = None
            for v in vars_iter:
                try:
                    if v.getName() == old_name:
                        target = v
                        break
                except Exception:
                    continue

            if target is None:
                return (
                    f"Error: variable '{old_name}' not found in function '{func_name}'"
                )

            desc = f"rename_variable: {func_name}.{old_name} -> {new_name}"
            tx = getattr(self._pyghidra, "transaction", None)
            tm_fn = getattr(self._pyghidra, "task_monitor", None)

            if callable(tx):
                monitor = tm_fn() if callable(tm_fn) else None
                with tx(self._program, desc):
                    target.setName(new_name, SourceType.USER_DEFINED)
                try:
                    if monitor is not None:
                        self._program.save(desc, monitor)
                except Exception:
                    pass
            else:
                target.setName(new_name, SourceType.USER_DEFINED)

            return f"Renamed variable '{old_name}' to '{new_name}' in function '{func_name}'"
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra renameVariable failed: %s", exc)
            return f"Error: pyGhidra renameVariable failed: {exc}"

    def _py_set_decompiler_comment(self, data: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        addr_str = data.get("address")
        comment = data.get("comment")
        if not addr_str or comment is None:
            return (
                "Error: 'address' and 'comment' are required for set_decompiler_comment"
            )

        try:
            from ghidra.program.model.listing import CodeUnit  # type: ignore[import]

            addr = self._py_addr_from_hex(str(addr_str))
            listing = self._program.getListing()
            cu = listing.getCodeUnitAt(addr)
            if cu is None:
                return f"Error: No code unit at address {addr_str}"

            desc = f"set_decompiler_comment at {addr_str}"
            tx = getattr(self._pyghidra, "transaction", None)
            tm_fn = getattr(self._pyghidra, "task_monitor", None)

            if callable(tx):
                monitor = tm_fn() if callable(tm_fn) else None
                with tx(self._program, desc):
                    cu.setComment(CodeUnit.PRE_COMMENT, comment)
                try:
                    if monitor is not None:
                        self._program.save(desc, monitor)
                except Exception:
                    pass
            else:
                cu.setComment(CodeUnit.PRE_COMMENT, comment)

            return f"Set decompiler comment at {addr_str}"
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra set_decompiler_comment failed: %s", exc)
            return f"Error: pyGhidra set_decompiler_comment failed: {exc}"

    def _py_set_disassembly_comment(self, data: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        addr_str = data.get("address")
        comment = data.get("comment")
        if not addr_str or comment is None:
            return "Error: 'address' and 'comment' are required for set_disassembly_comment"

        try:
            from ghidra.program.model.listing import CodeUnit  # type: ignore[import]

            addr = self._py_addr_from_hex(str(addr_str))
            listing = self._program.getListing()
            cu = listing.getCodeUnitAt(addr)
            if cu is None:
                return f"Error: No code unit at address {addr_str}"

            desc = f"set_disassembly_comment at {addr_str}"
            tx = getattr(self._pyghidra, "transaction", None)
            tm_fn = getattr(self._pyghidra, "task_monitor", None)

            if callable(tx):
                monitor = tm_fn() if callable(tm_fn) else None
                with tx(self._program, desc):
                    cu.setComment(CodeUnit.EOL_COMMENT, comment)
                try:
                    if monitor is not None:
                        self._program.save(desc, monitor)
                except Exception:
                    pass
            else:
                cu.setComment(CodeUnit.EOL_COMMENT, comment)

            return f"Set disassembly comment at {addr_str}"
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra set_disassembly_comment failed: %s", exc)
            return f"Error: pyGhidra set_disassembly_comment failed: {exc}"

    def _py_set_function_prototype(self, data: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        addr_str = data.get("function_address")
        prototype = data.get("prototype")
        if not addr_str or not prototype:
            return "Error: 'function_address' and 'prototype' are required for set_function_prototype"

        try:
            addr = self._py_addr_from_hex(str(addr_str))
            func = self._py_get_function_for_address(addr)
            if func is None:
                return f"Error: No function found at or containing address {addr_str}"

            desc = f"set_function_prototype at {addr_str}"
            tx = getattr(self._pyghidra, "transaction", None)
            tm_fn = getattr(self._pyghidra, "task_monitor", None)

            if hasattr(func, "setPrototypeString") and callable(tx):
                # Simple path with prototype string setter inside a transaction
                monitor = tm_fn() if callable(tm_fn) else None
                with tx(self._program, desc):
                    func.setPrototypeString(prototype)  # type: ignore[call-arg]
                try:
                    if monitor is not None:
                        self._program.save(desc, monitor)
                except Exception:
                    pass
                return f"Set prototype for function at {addr_str} to '{prototype}'"

            # Fallback: best-effort using C parser
            try:
                from ghidra.app.util.cparser.C import CParser  # type: ignore[import]
            except ImportError:
                return (
                    "Error: CParser not available to set function prototype; "
                    "consider upgrading Ghidra/pyGhidra."
                )

            from ghidra.program.model.symbol import SourceType  # type: ignore[import]

            dtm = self._program.getDataTypeManager()
            parser = CParser(dtm)
            func_dt = parser.parseFunction(prototype)

            ret_type = func_dt.getReturnType()
            params = func_dt.getArguments()

            if callable(tx):
                monitor = tm_fn() if callable(tm_fn) else None
                with tx(self._program, desc):
                    func.setReturnType(ret_type, SourceType.USER_DEFINED)
                    from ghidra.app.services import FunctionUpdateType  # type: ignore[import]

                    func.replaceParameters(
                        params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True
                    )
                try:
                    if monitor is not None:
                        self._program.save(desc, monitor)
                except Exception:
                    pass
            else:
                func.setReturnType(ret_type, SourceType.USER_DEFINED)
                from ghidra.app.services import FunctionUpdateType  # type: ignore[import]

                func.replaceParameters(
                    params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True
                )

            return f"Set prototype for function at {addr_str} to '{prototype}'"
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra set_function_prototype failed: %s", exc)
            return f"Error: pyGhidra set_function_prototype failed: {exc}"

    def _py_set_local_variable_type(self, data: Dict[str, Any]) -> str:
        if self._program is None:
            return "Error: pyGhidra program is not initialized"

        addr_str = data.get("function_address")
        var_name = data.get("variable_name")
        new_type = data.get("new_type")
        if not addr_str or not var_name or not new_type:
            return (
                "Error: 'function_address', 'variable_name', and 'new_type' are required "
                "for set_local_variable_type"
            )

        try:
            from ghidra.program.model.symbol import SourceType  # type: ignore[import]
            from ghidra.app.util.cparser.C import CParser  # type: ignore[import]

            addr = self._py_addr_from_hex(str(addr_str))
            func = self._py_get_function_for_address(addr)
            if func is None:
                return f"Error: No function found at or containing address {addr_str}"

            dtm = self._program.getDataTypeManager()
            parser = CParser(dtm)

            # Parse a temporary function prototype to extract the desired type
            proto_src = f"void __tmp({new_type} {var_name});"
            tmp_func_dt = parser.parseFunction(proto_src)
            args = tmp_func_dt.getArguments()
            if not args:
                return f"Error: Could not parse type '{new_type}'"
            desired_dt = args[0].getDataType()

            try:
                vars_iter = func.getAllVariables()
            except Exception:
                vars_iter = list(func.getParameters()) + list(func.getLocalVariables())

            target = None
            for v in vars_iter:
                try:
                    if v.getName() == var_name:
                        target = v
                        break
                except Exception:
                    continue

            if target is None:
                return (
                    f"Error: variable '{var_name}' not found in function at {addr_str}"
                )

            desc = f"set_local_variable_type for {var_name} at {addr_str}"
            tx = getattr(self._pyghidra, "transaction", None)
            tm_fn = getattr(self._pyghidra, "task_monitor", None)

            if callable(tx):
                monitor = tm_fn() if callable(tm_fn) else None
                with tx(self._program, desc):
                    target.setDataType(desired_dt, SourceType.USER_DEFINED)
                try:
                    if monitor is not None:
                        self._program.save(desc, monitor)
                except Exception:
                    pass
            else:
                target.setDataType(desired_dt, SourceType.USER_DEFINED)

            return (
                f"Set type of variable '{var_name}' in function at {addr_str} "
                f"to '{new_type}'"
            )
        except Exception as exc:  # pragma: no cover
            logger.error("pyGhidra set_local_variable_type failed: %s", exc)
            return f"Error: pyGhidra set_local_variable_type failed: {exc}"
