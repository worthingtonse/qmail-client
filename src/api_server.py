import http.server
import socketserver
import threading
import json
import os
import re
from urllib.parse import parse_qs, urlparse
from dataclasses import dataclass, field
from typing import Dict, List, Any, Tuple, Callable

# Try to import from package, fall back to direct import for standalone testing
try:
    from .logger import log_info, log_error, log_warning, log_debug
except ImportError:
    # Fallback for standalone testing (uses new 3-parameter API with context)
    def log_info(handle, context, msg): print(f"[INFO] [{context}] {msg}")
    def log_error(handle, context, msg, reason=None):
        if reason:
            print(f"[ERROR] [{context}] {msg} | REASON: {reason}")
        else:
            print(f"[ERROR] [{context}] {msg}")
    def log_warning(handle, context, msg): print(f"[WARNING] [{context}] {msg}")
    def log_debug(handle, context, msg): print(f"[DEBUG] [{context}] {msg}")

# Module context for logging
API_CONTEXT = "ApiServer"

# --- Constants ---
SERVER_NAME = "QMail-Client-Core/2.0"
MAX_REQUEST_SIZE = 1048576  # 1MB

@dataclass
class RequestContext:
    """
    A container for all request data passed to a handler.
    Decouples the handler from the http.server.BaseHTTPRequestHandler implementation.
    """
    method: str
    path: str
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    path_params: Dict[str, str] = field(default_factory=dict)
    body: bytes = b''
    json: Any = None
    headers: Dict[str, str] = field(default_factory=dict)
    client_address: Tuple[str, int] = ('', 0)

class APIServer:
    """
    A simple, multi-threaded HTTP server for the Qmail Client Core API.
    This server is designed with zero external dependencies and incorporates
    feedback from peer reviews for robustness.
    """
    def __init__(self, logger: Any, host: str = 'localhost', port: int = 8090, allowed_origins: List[str] = None):
        """
        Initializes the server but does not start it.

        Args:
            logger: A configured logger instance.
            host (str): The hostname or IP address to bind to.
            port (int): The port to listen on.
            allowed_origins (List[str]): List of allowed CORS origins. If None, uses default list.
        """
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port number: {port}. Must be between 1 and 65535.")

        self.logger = logger
        self.host = host
        self.port = port
        
        # Default allowed origins for CORS (development + production)
        if allowed_origins is None:
            self.allowed_origins = [
                # Development origins
                'http://localhost:5173',
                'http://127.0.0.1:5173',
                'http://localhost:3000',
                'http://127.0.0.1:3000',
                'http://localhost:8080',
                'http://127.0.0.1:8080',
                # Production origins
                'https://qmail.mycompany.com',         # Your actual domain
                'https://www.qmail.mycompany.com',     # www version
                'https://mail.mycompany.com',          # Alternative subdomain
            ]
        else:
            self.allowed_origins = allowed_origins
        
        def handler_factory(*args, **kwargs):
            return RequestHandler(self, *args, **kwargs)

        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.ThreadingTCPServer((self.host, self.port), handler_factory)
        
        self.thread = None
        self.routes = []
        self.routes_lock = threading.Lock()
        log_info(self.logger, API_CONTEXT, f"API Server initialized. Ready to start on {self.host}:{self.port}")
        log_info(self.logger, API_CONTEXT, f"CORS allowed origins: {', '.join(self.allowed_origins)}")

    def register_route(self, method: str, path_pattern: str, function: Callable[[RequestContext], None]):
        """
        Registers a function to handle a specific API route.

        Args:
            method (str): The HTTP method (e.g., 'GET', 'POST').
            path_pattern (str): The URL path pattern, which can include placeholders like '/users/{id}'.
            function (callable): The function to call. It receives a RequestContext object.
        """
        path_regex, param_names = self._compile_path_pattern(path_pattern)
        with self.routes_lock:
            self.routes.append({
                "method": method.upper(),
                "path_pattern": path_pattern,
                "path_regex": path_regex,
                "param_names": param_names,
                "handler": function
            })
        log_info(self.logger, API_CONTEXT, f"Route registered for {method.upper()} {path_pattern}")

    def _compile_path_pattern(self, path_pattern: str) -> Tuple[re.Pattern, List[str]]:
        """Converts a path pattern like /users/{id} to a regex."""
        param_names = re.findall(r'{(\w+)}', path_pattern)
        path_regex_str = re.sub(r'{\w+}', r'([^/]+)', path_pattern)
        return re.compile(f'^{path_regex_str}$'), param_names

    def start(self):
        """Starts the HTTP server in a background thread."""
        if self.thread is not None and self.thread.is_alive():
            log_warning(self.logger, API_CONTEXT, "Server is already running.")
            return

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        log_info(self.logger, API_CONTEXT, f"API Server started and listening on http://{self.host}:{self.port}")

    def stop(self):
        """Stops the HTTP server."""
        if self.thread is None or not self.thread.is_alive():
            log_info(self.logger, API_CONTEXT, "Server is not running.")
            return

        log_info(self.logger, API_CONTEXT, "API Server shutting down...")
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.thread = None
        log_info(self.logger, API_CONTEXT, "API Server has stopped.")


class RequestHandler(http.server.BaseHTTPRequestHandler):
    """
    Handles incoming HTTP requests, populates a RequestContext, and dispatches
    to the appropriate registered handler.
    """
    server_version = SERVER_NAME
    
    def __init__(self, server_instance: APIServer, *args, **kwargs):
        self.server_instance = server_instance
        self.logger = server_instance.logger
        super().__init__(*args, **kwargs)
    
    def _get_cors_origin(self):
        """
        Get appropriate CORS origin based on request Origin header.
        
        Returns:
            str: The origin to include in Access-Control-Allow-Origin header
        """
        origin = self.headers.get('Origin', '')
        
        # Check if origin is in allowed list
        if origin in self.server_instance.allowed_origins:
            return origin
        
        # Default to first allowed origin (for non-browser requests without Origin header)
        if self.server_instance.allowed_origins:
            return self.server_instance.allowed_origins[0]
        
        # Fallback
        return 'http://localhost:5173'
    

    def _parse_multipart(self, body, content_type):
     """Parse multipart/form-data without cgi module."""
     import re
    
    # Extract boundary from content-type
     boundary_match = re.search(r'boundary=([^;]+)', content_type)
     if not boundary_match:
        return {}, {}
    
     boundary = boundary_match.group(1).strip('"')
     boundary_bytes = ('--' + boundary).encode()
    
     files = {}
     data = {}
    
    # Split by boundary
     parts = body.split(boundary_bytes)
    
     for part in parts[1:-1]:  # Skip first empty and last closing boundary
        if not part.strip():
            continue
        
        # Split headers and content
        header_end = part.find(b'\r\n\r\n')
        if header_end == -1:
            continue
        
        headers = part[:header_end].decode('utf-8', errors='ignore')
        content = part[header_end + 4:]
        
        # Remove trailing \r\n
        if content.endswith(b'\r\n'):
            content = content[:-2]
        
        # Parse Content-Disposition header
        disp_match = re.search(r'Content-Disposition: form-data; name="([^"]+)"', headers)
        if not disp_match:
            continue
        
        field_name = disp_match.group(1)
        
        # Check if it's a file
        filename_match = re.search(r'filename="([^"]+)"', headers)
        
        if filename_match:
            # It's a file
            filename = filename_match.group(1)
            content_type_match = re.search(r'Content-Type: ([^\r\n]+)', headers)
            file_content_type = content_type_match.group(1) if content_type_match else 'application/octet-stream'
            
            files[field_name] = {
                'filename': filename,
                'content_type': file_content_type,
                'data': content
            }
        else:
            # It's regular form data
            data[field_name] = content.decode('utf-8', errors='ignore')
    
     return files, data
        
    def _dispatch(self):
        """
        Finds the handler, builds the RequestContext, and calls the handler.
        Differentiates between 404 Not Found and 405 Method Not Allowed.
        """
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        # Check for request size limit before doing anything else
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_REQUEST_SIZE:
            self.send_error(413, "Request Entity Too Large")
            return

        body = self.rfile.read(content_length) if content_length > 0 else b''

        matched_route = None
        path_params = {}
        
        with self.server_instance.routes_lock:
            for route in self.server_instance.routes:
                match = route["path_regex"].match(path)
                if match:
                    if self.command == route["method"]:
                        matched_route = route
                        path_params = dict(zip(route["param_names"], match.groups()))
                        break
        
        if matched_route:
            try:
                # Build the request context
                context = RequestContext(
                    method=self.command,
                    path=path,
                    query_params=parse_qs(parsed_url.query),
                    path_params=path_params,
                    body=body,
                    headers=dict(self.headers),
                    client_address=self.client_address
                )
                if 'application/json' in self.headers.get('Content-Type', ''):
                     context.json = json.loads(body) if body else None
                elif 'multipart/form-data' in self.headers.get('Content-Type', ''):
                      context.files, context.form_data = self._parse_multipart(body, self.headers.get('Content-Type'))

                # Call the handler with the context
                matched_route["handler"](self, context)
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON")
            except Exception as e:
                log_error(self.logger, API_CONTEXT, f"Error in handler for {self.command} {self.path}", str(e))
                self.send_error(500, "Internal Server Error")
            return

        # No route found, check if the path exists for other methods
        path_exists_for_other_method = False
        with self.server_instance.routes_lock:
            for route in self.server_instance.routes:
                if route["path_regex"].match(path):
                    path_exists_for_other_method = True
                    break
        
        if path_exists_for_other_method:
            self.send_error(405, "Method Not Allowed")
        else:
            self.send_error(404, "Not Found")

    def do_GET(self): self._dispatch()
    def do_POST(self): self._dispatch()
    def do_PUT(self): self._dispatch()
    def do_DELETE(self): self._dispatch()
    
    def do_OPTIONS(self):
        """Handle OPTIONS preflight requests for CORS."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', self._get_cors_origin())
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Max-Age', '3600')
        self.end_headers()
        
    def send_json_response(self, status_code: int, data: Any):
        """Sends a JSON response with CORS headers."""
        self.send_response(status_code)
        self.send_header("Content-type", "application/json")
        self.send_header("Server", self.server_version)
        # CORS headers
        self.send_header('Access-Control-Allow-Origin', self._get_cors_origin())
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def send_text_response(self, status_code: int, data: str):
        """Sends a plain text response with CORS headers."""
        self.send_response(status_code)
        self.send_header("Content-type", "text/plain")
        self.send_header("Server", self.server_version)
        # CORS headers
        self.send_header('Access-Control-Allow-Origin', self._get_cors_origin())
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        self.wfile.write(data.encode('utf-8'))


if __name__ == '__main__':
    import time
    # Import logger functions for standalone testing
    try:
        from .logger import init_logger, close_logger
        from .wallet_structure import initialize_wallet_structure
    except ImportError:
        # For standalone execution, try direct import
        import sys
        sys.path.insert(0, os.path.dirname(__file__))
        from logger import init_logger, close_logger
        from wallet_structure import initialize_wallet_structure

    # Ensure wallet folders exist
    initialize_wallet_structure()

    # --- Logger Setup ---
    log_dir = os.path.join(os.path.dirname(__file__), '..', 'Data')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    log_file_path = os.path.join(log_dir, 'mail.mlog')
    main_logger = init_logger(log_file_path)

    # --- Example Handlers (now accept RequestContext) ---
    def handle_status(request_handler: RequestHandler, context: RequestContext):
        """Example handler for a status route."""
        log_info(main_logger, API_CONTEXT, f"Handling GET /api/status request. Path params: {context.path_params}")
        response_data = {"status": "ok", "version": "3.0"}
        request_handler.send_json_response(200, response_data)

    def handle_get_user(request_handler: RequestHandler, context: RequestContext):
        """Example handler for getting a user by ID."""
        user_id = context.path_params.get('id')
        log_info(main_logger, API_CONTEXT, f"Handling GET /api/users/{user_id} request.")
        response_data = {"user_id": user_id, "name": f"User {user_id}", "query_params": context.query_params}
        request_handler.send_json_response(200, response_data)

    def handle_create_user(request_handler: RequestHandler, context: RequestContext):
        """Example handler for creating a user."""
        log_info(main_logger, API_CONTEXT, "Handling POST /api/users request.")
        if context.json is None:
            request_handler.send_error(400, "JSON body required")
            return

        user_name = context.json.get("name")
        response_data = {"message": f"User '{user_name}' created.", "id": int(time.time())}
        request_handler.send_json_response(201, response_data)

    # --- Server Setup ---
    PORT = 8090
    try:
        api_server = APIServer(logger=main_logger, host='localhost', port=PORT)
    except ValueError as e:
        log_error(main_logger, API_CONTEXT, "Failed to create API server", str(e))
        exit(1)

    # --- Route Registration ---
    api_server.register_route('GET', '/api/status', handle_status)
    api_server.register_route('GET', '/api/users/{id}', handle_get_user)
    api_server.register_route('POST', '/api/users', handle_create_user)
    # Add a route to test 405 Method Not Allowed
    api_server.register_route('GET', '/api/not_post', handle_status)

    # --- Start and Stop Server ---
    api_server.start()

    print(f"Server running on port {PORT}. Check {log_file_path} for details.")
    print("\nTry accessing:")
    print("  http://localhost:8090/api/status")
    print("  http://localhost:8090/api/users/123?verbose=true")
    print("\nTry posting:")
    print("  curl -X POST -H \"Content-Type: application/json\" -d '{\"name\": \"test\"}' http://localhost:8090/api/users")
    print("\nTry method not allowed (405):")
    print("  curl -X POST http://localhost:8090/api/not_post")
    print("\nPress Ctrl+C to stop the server.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping server...")
        api_server.stop()
        close_logger(main_logger)
        print("Server stopped.")