import os
import sys
import anyio

import fire
import mcp_openapi_proxy.utils

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
            path_name = path_name + "_" + pp

        if not path_parts:
            return "unknown_tool"

        name = f"{method}_{path_name}"
        return name if name else "unknown_tool"

    except ValueError:
        logger.debug(f"Failed to normalize tool name: {raw_name}")
        return "unknown_tool"

mcp_openapi_proxy.utils.normalize_tool_name = normalize_tool_name


from mcp import types
from mcp_openapi_proxy import server_lowlevel
from mcp.server.stdio import stdio_server
from mcp.server.models import InitializationOptions
from mcp.server.sse import SseServerTransport

import uvicorn

from starlette.applications import Starlette
from starlette.routing import Mount, Route

logger = server_lowlevel.logger

server = server_lowlevel.mcp
openapi_spec_data = server_lowlevel.openapi_spec_data
fetch_openapi_spec = server_lowlevel.fetch_openapi_spec
register_functions = server_lowlevel.register_functions
tools = server_lowlevel.tools
list_tools = server_lowlevel.list_tools
dispatcher_handler = server_lowlevel.dispatcher_handler
list_resources = server_lowlevel.list_resources
read_resource = server_lowlevel.read_resource
list_prompts = server_lowlevel.list_prompts
get_prompt = server_lowlevel.get_prompt


def start_sse_server(host: str, port: int) -> int:
    logger.debug("Starting Low-Level MCP SSE server...")
    sse = SseServerTransport("/messages/")

    async def handle_sse(request):
        async with sse.connect_sse(
                request.scope, request.receive, request._send
        ) as streams:
            await server.run(
                streams[0],
                streams[1],
                server.create_initialization_options(),
                # initialization_options=InitializationOptions(
                #     server_name="AnyOpenAPIMCP-LowLevel",
                #     server_version="0.1.0",
                #     capabilities=types.ServerCapabilities(
                #         tools=types.ToolsCapability(listChanged=True),
                #         prompts=types.PromptsCapability(listChanged=True),
                #         resources=types.ResourcesCapability(listChanged=True)
                #     ),
                # ),
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


async def start_server():
    logger.debug("Starting Low-Level MCP server...")
    async with stdio_server() as (read_stream, write_stream):
        while True:
            try:
                await server.run(
                    read_stream,
                    write_stream,
                    initialization_options=InitializationOptions(
                        server_name="AnyOpenAPIMCP-LowLevel",
                        server_version="0.1.0",
                        capabilities=types.ServerCapabilities(
                            tools=types.ToolsCapability(listChanged=True),
                            prompts=types.PromptsCapability(listChanged=True),
                            resources=types.ResourcesCapability(listChanged=True)
                        ),
                    ),
                )
            except Exception as e:
                logger.error(f"MCP run crashed: {e}", exc_info=True)
                await anyio.sleep(1)  # Wait a sec, then retry

def setup_and_start_server(host: str, port: int) -> int:
    try:
        openapi_url = os.getenv('OPENAPI_SPEC_URL')
        if not openapi_url:
            logger.critical("OPENAPI_SPEC_URL environment variable is required but not set.")
            sys.exit(1)
        openapi_spec_data = fetch_openapi_spec(openapi_url)
        if not openapi_spec_data:
            logger.critical("Failed to fetch or parse OpenAPI specification from OPENAPI_SPEC_URL.")
            sys.exit(1)
        logger.debug("OpenAPI specification fetched successfully.")
        register_functions(openapi_spec_data)
        logger.debug(f"Tools after registration: {[tool.name for tool in tools]}")
        if not tools:
            logger.critical("No valid tools registered. Shutting down.")
            sys.exit(1)
        server.request_handlers[types.ListToolsRequest] = list_tools
        server.request_handlers[types.CallToolRequest] = dispatcher_handler
        server.request_handlers[types.ListResourcesRequest] = list_resources
        server.request_handlers[types.ReadResourceRequest] = read_resource
        server.request_handlers[types.ListPromptsRequest] = list_prompts
        server.request_handlers[types.GetPromptRequest] = get_prompt
        logger.debug("Handlers registered.")
        return start_sse_server(host, port)
    except KeyboardInterrupt:
        logger.debug("MCP server shutdown initiated by user.")
    except Exception as e:
        logger.critical(f"Failed to start MCP server: {e}", exc_info=True)
        sys.exit(1)
    return 1

def main(host: str, port: int) -> int:
    return setup_and_start_server(host, port)


if __name__ == "__main__":
    fire.Fire(main)