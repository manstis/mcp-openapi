import os
import fire
import json
import requests
import yaml
import sys
import mcp.types as types
import uvicorn

from mcp.server.lowlevel import Server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from typing import List, Dict, Optional

from mcp_openapi_proxy.utils import setup_logging


DEBUG = os.getenv("DEBUG", "").lower() in ("true", "1", "yes")
logger = setup_logging(debug=DEBUG)

tools: List[types.Tool] = []

def main(host: str, port: int) -> int:
    server = Server("manstis-mcp-weather-tool")

    @server.call_tool()
    async def echo_tool(
            name: str, arguments: dict
    ) -> list[types.TextContent]:
        logger.warning(f"--> Tool call {name}, {arguments}")
        if name != "echo":
            raise ValueError(f"Unknown tool: {name}")
        if "echo" not in arguments:
            raise ValueError("Missing required argument 'echo'")
        return [types.TextContent(type="text", text=f"{arguments["echo"]}... is there an echo? {arguments["echo"]}... ")]

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        logger.warning(f"--> Returning tools {tools}")
        return tools

    sse = SseServerTransport("/messages/")

    async def handle_sse(request):
        async with sse.connect_sse(
                request.scope, request.receive, request._send
        ) as streams:
            await server.run(
                streams[0], streams[1], server.create_initialization_options()
            )

    starlette_app = Starlette(
        debug=True,
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
    )

    uvicorn.run(starlette_app, host=host, port=port)

    return 0


def load_openapi_spec() -> Optional[Dict]:
    openapi_url = os.getenv('OPENAPI_SPEC_URL')
    if not openapi_url:
        logger.critical("OPENAPI_SPEC_URL environment variable is required but not set.")
        sys.exit(1)
    load_openapi_spec = fetch_openapi_spec(openapi_url)
    if not load_openapi_spec:
        logger.critical("Failed to fetch or parse OpenAPI specification from OPENAPI_SPEC_URL.")
        sys.exit(1)
    logger.debug("OpenAPI specification fetched successfully.")
    return load_openapi_spec


def fetch_openapi_spec(url: str, retries: int = 3) -> Optional[Dict]:
    """Fetch and parse an OpenAPI specification from a URL with retries."""
    logger.debug(f"Fetching OpenAPI spec from URL: {url}")
    attempt = 0
    while attempt < retries:
        try:
            if url.startswith("file://"):
                with open(url[7:], "r") as f:
                    content = f.read()
            else:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                content = response.text
            logger.debug(f"Fetched content length: {len(content)} bytes")
            try:
                spec = json.loads(content)
                logger.debug(f"Parsed as JSON from {url}")
            except json.JSONDecodeError:
                try:
                    spec = yaml.safe_load(content)
                    logger.debug(f"Parsed as YAML from {url}")
                except yaml.YAMLError as ye:
                    logger.error(f"YAML parsing failed: {ye}. Raw content: {content[:500]}...")
                    return None
            return spec
        except requests.RequestException as e:
            attempt += 1
            logger.warning(f"Fetch attempt {attempt}/{retries} failed: {e}")
            if attempt == retries:
                logger.error(f"Failed to fetch spec from {url} after {retries} attempts: {e}")
                return None
    return None


def parse_tools(spec: Dict) -> List[types.Tool]:
    """Register tools from OpenAPI spec, preserving across calls if already populated."""
    tools: List[types.Tool] = []
    logger.debug("Clearing previously registered tools to allow re-registration")
    tools.clear()
    if not spec:
        logger.error("OpenAPI spec is None or empty.")
        return tools
    if 'paths' not in spec:
        logger.error("No 'paths' key in OpenAPI spec.")
        return tools
    logger.debug(f"Spec paths available: {list(spec['paths'].keys())}")
    filtered_paths = {path: item for path, item in spec['paths'].items() if is_tool_whitelisted(path)}
    logger.debug(f"Filtered paths: {list(filtered_paths.keys())}")
    if not filtered_paths:
        logger.warning("No whitelisted paths found in OpenAPI spec after filtering.")
        return tools
    for path, path_item in filtered_paths.items():
        if not path_item:
            logger.debug(f"Empty path item for {path}")
            continue
        for method, operation in path_item.items():
            if method.lower() not in ['get', 'post', 'put', 'delete', 'patch']:
                logger.debug(f"Skipping unsupported method {method} for {path}")
                continue
            try:
                raw_name = f"{method.upper()} {path}"
                function_name = normalize_tool_name(raw_name)
                description = operation.get('summary', operation.get('description', 'No description available'))
                input_schema = {
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False
                }
                parameters = operation.get('parameters', [])
                placeholder_params = [part.strip('{}') for part in path.split('/') if '{' in part and '}' in part]
                for param_name in placeholder_params:
                    input_schema['properties'][param_name] = {
                        "type": "string",
                        "description": f"Path parameter {param_name}"
                    }
                    input_schema['required'].append(param_name)
                    logger.debug(f"Added URI placeholder {param_name} to inputSchema for {function_name}")
                for param in parameters:
                    param_name = param.get('name')
                    param_in = param.get('in')
                    if param_in in ['path', 'query']:
                        param_type = param.get('schema', {}).get('type', 'string')
                        schema_type = param_type if param_type in ['string', 'integer', 'boolean', 'number'] else 'string'
                        input_schema['properties'][param_name] = {
                            "type": schema_type,
                            "description": param.get('description', f"{param_in} parameter {param_name}")
                        }
                        if param.get('required', False) and param_name not in input_schema['required']:
                            input_schema['required'].append(param_name)
                tool = types.Tool(
                    name=function_name,
                    description=description,
                    inputSchema=input_schema,
                )
                tools.append(tool)
                logger.debug(f"Registered function: {function_name} ({method.upper()} {path}) with inputSchema: {json.dumps(input_schema)}")
            except Exception as e:
                logger.error(f"Error registering function for {method.upper()} {path}: {e}", exc_info=True)
    logger.debug(f"Registered {len(tools)} functions from OpenAPI spec.")
    return tools


def normalize_tool_name(raw_name: str) -> str:
    """Convert an HTTP method and path into a normalized tool name."""
    try:
        method, path = raw_name.split(" ", 1)
        method = method.lower()

        path_name = ""
        path_parts = path.split("/")
        for path_part in path_parts:
            pp = path_part
            if pp.startswith("{"):
                pp = pp[1:]
            if pp.endswith("}"):
                pp = pp[:-1]
            path_name = path_name + " " + pp

        if not path_parts:
            return "unknown_tool"

        name = f"{method} {path_name}"
        return name if name else "unknown_tool"

    except ValueError:
        logger.debug(f"Failed to normalize tool name: {raw_name}")
        return "unknown_tool"


def is_tool_whitelisted(endpoint: str) -> bool:
    """Check if an endpoint is allowed based on TOOL_WHITELIST."""
    whitelist = os.getenv("TOOL_WHITELIST")
    logger.debug(f"Checking whitelist - endpoint: {endpoint}, TOOL_WHITELIST: {whitelist}")
    if not whitelist:
        logger.debug("No TOOL_WHITELIST set, allowing all endpoints.")
        return True
    import re
    whitelist_entries = [entry.strip() for entry in whitelist.split(",")]
    for entry in whitelist_entries:
        if "{" in entry:
            # Build a regex pattern from the whitelist entry by replacing placeholders with a non-empty segment match ([^/]+)
            pattern = re.escape(entry)
            pattern = re.sub(r"\\\{[^\\\}]+\\\}", r"([^/]+)", pattern)
            pattern = "^" + pattern + "($|/.*)$"
            if re.match(pattern, endpoint):
                logger.debug(f"Endpoint {endpoint} matches whitelist entry {entry} using regex {pattern}")
                return True
        else:
            if endpoint.startswith(entry):
                logger.debug(f"Endpoint {endpoint} matches whitelist entry {entry}")
                return True
    logger.debug(f"Endpoint {endpoint} not in whitelist - skipping.")
    return False


if __name__ == "__main__":
    spec: Optional[Dict] = load_openapi_spec()
    tools = parse_tools(spec)
    fire.Fire(main)