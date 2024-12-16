# snippets.py

import os
import tempfile
import shutil
import subprocess
import json
import threading
import http.server
import socketserver
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Tuple
import logging
import requests
import atexit
import ctypes

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class RustGenerator(ABC):
    """
    Abstract base class for Rust code generation.
    """
    @abstractmethod
    def generate_rust_code(self, func_name: str, arg_types: List[str], return_type: str, func_body: str, use_server: bool = False) -> str:
        """
        Generates Rust code for a specified function with FFI bindings.

        Args:
            func_name (str): The name of the Rust function.
            arg_types (List[str]): A list of Rust data types for the function's arguments.
            return_type (str): The Rust data type for the function's return value.
            func_body (str): The Rust code that defines the function's logic.
            use_server (bool): If True the function is assumed to run on the server, if false run locally.

        Returns:
            str: The generated Rust code as a string.
        """
        pass

    @abstractmethod
    def compile_rust_code(self, rust_code: str, lib_name: str, output_dir: str) -> str:
        """
        Compiles Rust code into a dynamic library (.so, .dylib).

        Args:
            rust_code (str): The Rust code to compile.
            lib_name (str): The base name for the output library (e.g., 'my_lib').
            output_dir (str): The directory to save the compiled library.

        Returns:
            str: The full path to the compiled dynamic library.
        """
        pass


class CTypesGenerator(ABC):
    """
    Abstract base class for generating Python ctypes interface code.
    """
    @abstractmethod
    def generate_ctypes_code(self, lib_path: str, func_name: str, arg_types: List[str], return_type: str, use_server:bool = False) -> str:
        """
        Generates Python ctypes code for interfacing with a dynamic library.

        Args:
            lib_path (str): The full path to the compiled dynamic library.
            func_name (str): The name of the function in the library to interface with.
            arg_types (List[str]): A list of Python data types to map to the Rust arguments.
            return_type (str): A Python data type corresponding to the return type of the rust function.
            use_server (bool): If True the function is assumed to run on the server, if false run locally.

        Returns:
            str: The generated Python ctypes code as a string.
        """
        pass


class IOSSigner(ABC):
    """
    Abstract base class for signing iOS dynamic libraries.
    """

    @abstractmethod
    def sign_library(self, lib_path: str, team_id: str, code_sign_identity: str, provision_profile: str, server_url: str = None, auth_token: str = None) -> str:
        """
        Signs a dynamic library for iOS deployment, either locally or through a signing server.

        Args:
            lib_path (str): The path to the dynamic library to sign.
            team_id (str): The Apple Developer Team ID.
            code_sign_identity (str): The code signing identity (e.g., "iPhone Developer: ...").
            provision_profile (str): The path to the mobile provisioning profile.
            server_url (str, optional): The URL of the signing server if using one, default is None.
            auth_token (str, optional): The authentication token for the signing server, default is None.

        Returns:
             str: The path to the signed library.
        """
        pass


class ServerConnector(ABC):
    """
    Abstract base class for communicating with servers.
    """
    @abstractmethod
    def send_request(self, url: str, method: str, headers: Dict[str, str], data: Dict[str, Any]) -> Tuple[int, str]:
        """
        Sends a request to a server and returns the response.

        Args:
            url (str): The URL of the server.
            method (str): The HTTP method (e.g., "POST", "GET").
            headers (Dict[str, str]): Request headers.
            data (Dict[str, Any]): Request payload as a dictionary.

        Returns:
            Tuple[int, str]: A tuple containing the HTTP status code and the response body.
        """
        pass


class LibraryManager(ABC):
    """
    Abstract base class for local storage of libraries
    """
    @abstractmethod
    def store_library(self, lib_path: str, library_name: str) -> str:
        """
        Stores a compiled library to a local directory.

        Args:
            lib_path (str): The path to the compiled dynamic library.
            library_name (str): The name to give the library during local storage.

        Returns:
            str: The path to where the library was stored
        """
        pass

    @abstractmethod
    def load_library(self, library_name: str) -> str:
        """
        Loads a compiled library from a local directory.

        Args:
            library_name (str): The name of the library to load.

        Returns:
            str: The path to the loaded library.
        """
        pass


class PassthroughSystem(ABC):
    """
    Abstract base class for determining whether to process a call locally or on a server.
    """
    @abstractmethod
    def should_use_server(self, func_name: str, args: List[Any]) -> bool:
        """
        Determines whether to process a function call locally or on a server.

        Args:
            func_name (str): The name of the function to execute.
            args (List[Any]): Arguments for the function.

        Returns:
            bool: True if the function should be executed on the server, False otherwise.
        """
        pass


class API_SERVER(ABC):
    """
    Abstract base class for the API server used for running rust logic
    """
    @abstractmethod
    def start(self) -> None:
        """
        Starts the API server
        """
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """
        Shuts down the API server
        """
        pass


class SIGNING_SERVER(ABC):
    """
    Abstract base class for the Signing server to sign dynamic libraries
    """
    @abstractmethod
    def start(self) -> None:
        """
        Starts the signing server
        """
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """
        Shuts down the signing server
        """
        pass


class RustPythonIntegration:
    """
    Main class for integrating Rust, ctypes, iOS signing, server interactions, and library management.
    """
    def __init__(self, rust_generator: RustGenerator, c_types_generator: CTypesGenerator, ios_signer: IOSSigner, server_connector: ServerConnector, library_manager: LibraryManager, passthrough_system: PassthroughSystem, api_server: API_SERVER, signing_server: SIGNING_SERVER):
        """
        Initializes the RustPythonIntegration with all required components.

        Args:
            rust_generator (RustGenerator): Rust code generator instance.
            c_types_generator (CTypesGenerator): ctypes code generator instance.
            ios_signer (IOSSigner): iOS code signing instance.
            server_connector (ServerConnector): Server communication instance.
            library_manager (LibraryManager): Library storage instance.
            passthrough_system (PassthroughSystem): Determines whether to run local or server logic
            api_server (API_SERVER): Handles executing rust logic remotely
            signing_server (SIGNING_SERVER): Handles signing dynamic libraries remotely
        """
        self.rust_generator = rust_generator
        self.ctypes_generator = c_types_generator
        self.ios_signer = ios_signer
        self.server_connector = server_connector
        self.library_manager = library_manager
        self.passthrough_system = passthrough_system
        self.api_server = api_server
        self.signing_server = signing_server
        self.api_server_url = "http://127.0.0.1:8000"
        self.signing_server_url = "http://127.0.0.1:8001"
        self.auth_token = "secure_auth_token"  # Placeholder auth token

    def start_servers(self):
        """Starts the local api server and signing server"""
        self.api_server.start()
        self.signing_server.start()

    def shutdown_servers(self):
        """Shuts down the local api server and signing server"""
        self.api_server.shutdown()
        self.signing_server.shutdown()

    def create_rust_function(self, func_name: str, arg_types: List[str], return_type: str, func_body: str, args: List[Any] = None) -> str:
        """
        Creates a Rust function by generating, compiling, and storing the dynamic library.
         Uses a `PassthroughSystem` to determine if the function is run locally or remotely.

        Args:
            func_name (str): The name of the Rust function.
            arg_types (List[str]): A list of Rust data types for the function's arguments.
            return_type (str): The Rust data type for the function's return value.
            func_body (str): The Rust code that defines the function's logic.
            args (List[Any], Optional): Arguments for the function that may be used for the passthrough logic.

        Returns:
            str: The full path to the compiled dynamic library.

        Raises:
            Exception: If the Rust code fails to compile
        """
        if args is None:
            args = []  # Ensure an empty args array to avoid errors
        
        use_server = self.passthrough_system.should_use_server(func_name, args)
        # 1. Generate Rust code
        rust_code = self.rust_generator.generate_rust_code(func_name, arg_types, return_type, func_body, use_server)
        
        # 2. Compile Rust code
        lib_name = f"{func_name}_lib"
        lib_path = self.rust_generator.compile_rust_code(rust_code, lib_name, tempfile.gettempdir())
        if not lib_path:
            raise Exception("Failed to compile Rust code.")

        return lib_path

    def create_ctypes_interface(self, lib_path: str, func_name: str, arg_types: List[str], return_type: str, use_server: bool = False) -> str:
        """
        Generates Python ctypes code for interfacing with a dynamic library, handles both local and remote calls.

        Args:
            lib_path (str): The full path to the compiled dynamic library.
            func_name (str): The name of the function in the library to interface with.
            arg_types (List[str]): A list of Python data types to map to the Rust arguments.
            return_type (str): A Python data type corresponding to the return type of the rust function.
            use_server (bool): If True the function is assumed to run on the server, if false run locally.

        Returns:
             str: The generated Python ctypes code as a string.
        """
        # 3. Generate Python ctypes code
        ctypes_code = self.ctypes_generator.generate_ctypes_code(lib_path, func_name, arg_types, return_type, use_server)
        return ctypes_code

    def sign_ios_library(self, lib_path: str, team_id: str, code_sign_identity: str, provision_profile: str) -> str:
        """
        Signs an iOS dynamic library using local signing or a remote signing server.

        Args:
            lib_path (str): The full path to the compiled dynamic library to sign.
            team_id (str): The Apple Developer Team ID.
            code_sign_identity (str): The code signing identity (e.g., "iPhone Developer: ...").
            provision_profile (str): The path to the mobile provisioning profile.

        Returns:
             str: The path to the signed library.
        """
        # 4. Sign the iOS dynamic library
        signed_lib_path = self.ios_signer.sign_library(lib_path, team_id, code_sign_identity, provision_profile, server_url=self.signing_server_url, auth_token=self.auth_token)
        return signed_lib_path
    
    def send_request_to_server(self, url: str, method: str, headers: Dict[str, str], data: Dict[str, Any]) -> Tuple[int, str]:
        """
        Sends a request to a server.

        Args:
           url (str): The URL of the server.
           method (str): The HTTP method (e.g., "POST", "GET").
           headers (Dict[str, str]): Request headers.
           data (Dict[str, Any]): Request payload as a dictionary.

        Returns:
            Tuple[int, str]: A tuple containing the HTTP status code and the response body.
        """
        # 5. Send data to the server
        response_code, response_data = self.server_connector.send_request(url, method, headers, data)
        return response_code, response_data
    
    def store_compiled_library(self, lib_path: str, library_name: str) -> str:
        """
        Stores a compiled library to local storage.

        Args:
            lib_path (str): The path to the compiled dynamic library.
            library_name (str): The name to give the library during local storage.

        Returns:
            str: The path to where the library was stored.
        """
        # 6. Store compiled library
        stored_lib_path = self.library_manager.store_library(lib_path, library_name)
        return stored_lib_path

    def load_compiled_library(self, library_name: str) -> str:
        """
        Loads a compiled library from local storage.

        Args:
            library_name (str): The name of the library to load.

        Returns:
            str: The path to the loaded library.
        """
        # 7. Load the compiled library
        loaded_lib_path = self.library_manager.load_library(library_name)
        return loaded_lib_path
    
    def execute_rust_function_server(self, lib_path: str, func_name: str, arg_types: List[str], return_type: str, args: List[Any]) -> Any:
        """
        Executes a Rust function on the remote server, and returns the result

        Args:
            lib_path (str): The path to the compiled dynamic library.
            func_name (str): The name of the function to run.
            arg_types (List[str]): A list of Rust data types for the function's arguments.
            return_type (str): The Rust data type for the function's return value.
            args (List[Any]): Arguments for the function.

        Returns:
            Any: The return result from the server.

        Raises:
            Exception: If the server encounters an error, it will output the server error response.
        """
        """Execute a rust function by sending to the server"""
        url = f"{self.api_server_url}/execute"
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.auth_token}"}
        data = {
            "lib_path": lib_path,
            "func_name": func_name,
            "arg_types": arg_types,
            "return_type": return_type,
            "args": args
        }
        
        response_code, response_data = self.send_request_to_server(url, "POST", headers, data)

        if response_code == 200:
            try:
                return json.loads(response_data).get('result')
            except:
                return response_data
        else:
            raise Exception(f"Error on server execution: Status Code - {response_code}, Message: {response_data}")
# Concrete Class Implementations (No changes from previous example)
class ConcreteRustGenerator(RustGenerator):
    def generate_rust_code(self, func_name: str, arg_types: List[str], return_type: str, func_body: str, use_server:bool = False) -> str:
        if use_server:
            rust_args = ", ".join([f"arg{i}: {arg_type}" for i, arg_type in enumerate(arg_types)])
            rust_ffi_args = ", ".join([f"arg{i}" for i in range(len(arg_types))])
            return f"""
            #[no_mangle]
            pub extern "C" fn {func_name}({rust_args}) -> {return_type} {{
                {func_body}
            }}
            """
        else:
          rust_args = ", ".join([f"arg{i}: {arg_type}" for i, arg_type in enumerate(arg_types)])
          rust_ffi_args = ", ".join([f"arg{i}" for i in range(len(arg_types))])
          return f"""
          #[no_mangle]
          pub extern "C" fn {func_name}({rust_args}) -> {return_type} {{
            {func_body}
          }}
          """

    def compile_rust_code(self, rust_code: str, lib_name: str, output_dir: str) -> str:
        temp_rust_file = os.path.join(tempfile.gettempdir(), f"{lib_name}.rs")
        with open(temp_rust_file, "w") as f:
            f.write(rust_code)

        lib_path = os.path.join(output_dir, f"lib{lib_name}.dylib") #For macOS
        try:
            subprocess.run(
                ["rustc", "--crate-type", "cdylib", temp_rust_file, "-o", lib_path],
                check=True,
                capture_output=True
                )
            return lib_path
        except subprocess.CalledProcessError as e:
          print(f"Error compiling rust code: {e.stderr.decode()}")
          return None

class ConcreteCTypesGenerator(CTypesGenerator):
    def generate_ctypes_code(self, lib_path: str, func_name: str, arg_types: List[str], return_type: str, use_server: bool = False) -> str:
        arg_defs = ", ".join([f"{arg_type}" for arg_type in arg_types])
        if use_server:
            return f"""
import ctypes
import json
import requests

lib = ctypes.CDLL("{lib_path}")

def {func_name}(*args):
    return None # This call will be handled by the server
"""
        else:
            return f"""
import ctypes

lib = ctypes.CDLL("{lib_path}")
{func_name} = lib.{func_name}
{func_name}.argtypes = [{arg_defs}]
{func_name}.restype = {return_type}
"""


class ConcreteIOSSigner(IOSSigner):
    def sign_library(self, lib_path: str, team_id: str, code_sign_identity: str, provision_profile: str, server_url: str = None, auth_token: str = None) -> str:
        if server_url:
            try:
                url = f"{server_url}/sign"
                headers = {"Content-Type": "application/json", "Authorization": f"Bearer {auth_token}"}
                data = {
                    "lib_path": lib_path,
                    "team_id": team_id,
                    "code_sign_identity": code_sign_identity,
                    "provision_profile": provision_profile,
                }
                response_code, response_data = requests.post(url, headers=headers, json=data)
                
                if response_code == 200:
                    return response_data
                else:
                    raise Exception(f"Error signing on server: Status Code - {response_code}, Message: {response_data}")
            except Exception as e:
                logging.error(f"Error communicating with signing server: {e}")
                return None
        else:
            try:
                signed_lib_path = os.path.join(tempfile.gettempdir(), f"signed_{os.path.basename(lib_path)}")
                subprocess.run(
                    [
                        "codesign",
                        "--force",
                        "--sign",
                        code_sign_identity,
                        "--entitlements",
                        f'<(dict)(key)com.apple.security.cs.allow-jit(true)(/key)(/dict)>',
                        "--options=runtime",
                        "--timestamp=none",
                        "--identifier",
                        "com.example.rustlib", #Update to a configurable identifier
                        lib_path,
                    ],
                    check=True,
                    capture_output=True
                )
                subprocess.run([
                    "cp", lib_path, signed_lib_path
                ])
                return signed_lib_path
            except subprocess.CalledProcessError as e:
                print(f"Error signing library: {e.stderr.decode()}")
                return None


class ConcreteServerConnector(ServerConnector):
    def send_request(self, url: str, method: str, headers: Dict[str, str], data: Dict[str, Any]) -> Tuple[int, str]:
        try:
            response = requests.request(method, url, headers=headers, json=data)
            response.raise_for_status()
            return response.status_code, response.text
        except requests.exceptions.RequestException as e:
            print(f"Error during server request: {e}")
            return 0, str(e)


class ConcreteLibraryManager(LibraryManager):
    def __init__(self):
        self.library_directory = os.path.join(tempfile.gettempdir(), "rust_libraries")
        os.makedirs(self.library_directory, exist_ok=True)
    
    def store_library(self, lib_path: str, library_name: str) -> str:
        stored_path = os.path.join(self.library_directory, library_name)
        try:
            shutil.copy(lib_path, stored_path)
            return stored_path
        except Exception as e:
            print(f"Error storing the library: {e}")
            return None

    def load_library(self, library_name: str) -> str:
        lib_path = os.path.join(self.library_directory, library_name)
        if os.path.exists(lib_path):
            return lib_path
        else:
            print(f"Library: {library_name}, was not found")
            return None


class ConcretePassthroughSystem(PassthroughSystem):
    def should_use_server(self, func_name: str, args: List[Any]) -> bool:
        # For demonstration purposes, use the server if a function name contains "server"
        return "server" in func_name.lower()

class SimpleAPIHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.rust_integrator = kwargs.pop('rust_integrator', None)
        super().__init__(*args, **kwargs)

    def do_POST(self):
        if self.path == "/execute":
            self.handle_execute()
        else:
            self.send_response(404)
            self.end_headers()
    
    def handle_execute(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        data = json.loads(post_data)

        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Unauthorized"}).encode("utf-8"))
            return

        auth_token = auth_header.split(" ")[1]
        if auth_token != self.rust_integrator.auth_token:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Forbidden"}).encode("utf-8"))
            return
        try:
            lib_path = data.get("lib_path")
            func_name = data.get("func_name")
            arg_types = data.get("arg_types")
            return_type = data.get("return_type")
            args = data.get("args")
            ctypes_code = self.rust_integrator.create_ctypes_interface(lib_path, func_name, arg_types, return_type, use_server=True)
            with open(os.path.join(tempfile.gettempdir(), "server_temp_ctypes.py"), "w") as f:
                f.write(ctypes_code)
            
            # Temporarily import the generated ctypes code so we can call the functions
            import sys
            sys.path.append(tempfile.gettempdir())
            import server_temp_ctypes
            sys.path.remove(tempfile.gettempdir()) #Remove so it can't be called elsewhere

            result = getattr(server_temp_ctypes, func_name)(*args)


            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"result": result}).encode("utf-8"))
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))


class ConcreteAPIServer(API_SERVER):
    def __init__(self, rust_integrator: RustPythonIntegration):
        self.port = 8000
        self.rust_integrator = rust_integrator
        self.httpd = None
        self.server_thread = None

    def start(self):
        handler = lambda *args, **kwargs: SimpleAPIHandler(*args, **kwargs, rust_integrator=self.rust_integrator)
        self.httpd = socketserver.TCPServer(("127.0.0.1", self.port), handler)
        self.server_thread = threading.Thread(target=self.httpd.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        logging.info("API Server Started")

    def shutdown(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.server_thread.join()
            logging.info("API Server Shutdown")


class SimpleSigningHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.rust_integrator = kwargs.pop('rust_integrator', None)
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        if self.path == "/sign":
            self.handle_sign()
        else:
            self.send_response(404)
            self.end_headers()
    
    def handle_sign(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        data = json.loads(post_data)
        
        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Unauthorized"}).encode("utf-8"))
            return

        auth_token = auth_header.split(" ")[1]
        if auth_token != self.rust_integrator.auth_token:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Forbidden"}).encode("utf-8"))
            return

        try:
            lib_path = data.get("lib_path")
            team_id = data.get("team_id")
            code_sign_identity = data.get("code_sign_identity")
            provision_profile = data.get("provision_profile")
            signed_lib_path = os.path.join(tempfile.gettempdir(), f"signed_server_{os.path.basename(lib_path)}")
            subprocess.run(
                [
                    "codesign",
                    "--force",
                    "--sign",
                    code_sign_identity,
                    "--entitlements",
                    f'<(dict)(key)com.apple.security.cs.allow-jit(true)(/key)(/dict)>',
                    "--options=runtime",
                    "--timestamp=none",
                    "--identifier",
                    "com.example.rustlib", #Update to a configurable identifier
                    lib_path,
                ],
                check=True,
                capture_output=True
            )
            subprocess.run([
                "cp", lib_path, signed_lib_path
            ])
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(signed_lib_path).encode("utf-8"))
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))


class ConcreteSigningServer(SIGNING_SERVER):
    def __init__(self, rust_integrator: RustPythonIntegration):
        self.port = 8001
        self.rust_integrator = rust_integrator
        self.httpd = None
        self.server_thread = None
    
    def start(self):
        handler = lambda *args, **kwargs: SimpleSigningHandler(*args, **kwargs, rust_integrator=self.rust_integrator)
        self.httpd = socketserver.TCPServer(("127.0.0.1", self.port), handler)
        self.server_thread = threading.Thread(target=self.httpd.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        logging.info("Signing Server Started")

    def shutdown(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.server_thread.join()
            logging.info("Signing Server Shutdown")
