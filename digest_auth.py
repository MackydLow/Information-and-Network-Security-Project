#imports 
from ..common import RequestHandlerABC, RequestHandler, HeaderContainer, NO_CACHE_HEADERS
from ..http.request import HTTPRequest
from ..http.response import HTTPResponseFactory
from ..networking import ConnectionInfo
from .. import log
import hashlib, hmac
import secrets, time
from urllib.request import parse_http_list, parse_keqv_list

#messages appear in server's log output
LOG = log.getLogger("middlewares.digest_auth")

#nonce is alive for 300 seconds, after this client gets a new 401 challenge with a fresh nonce
NONCE_LIFETIME = 300
"""Middle ware that implements HTTP Digest Authentication."""
class DigestAuthMiddleware(RequestHandlerABC):
    """Set up the middleware and load the user directory from the password file"""
    def __init__(self, next: RequestHandler, pwdfile: str):
        self.next = next #process request once they are authenticated
        self.pwdfile = pwdfile #remeber where password file is
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)
        self.users: dict[str, str] = {}

        #read the password file and fill directory
        with open(self.pwdfile, encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line or ":" not in line:
                    continue #skip blank line or malformed line
                username, pw_hash = line.split(":", 1) #split on the first colon
                self.users[username] = pw_hash.lower() #store hash in lowercase

        self.realm = "py_http_server"
        self.nonces: dict[str, float] = {}

    """Create a new random nonce record when it was issued and return"""
    def _generate_nonce(self) -> str:
        nonce = secrets.token_hex(16)
        self.nonces[nonce] = time.time()
        return nonce

    """Build a 401 unathorized response containing a fresh Digest challenge"""
    def _unauthorized(self):
        challenge = (
            f'Digest realm="{self.realm}", qop="auth", '
            f'algorithm=SHA-256, nonce="{self._generate_nonce()}"'
        )
        return self.http.status(401, HeaderContainer({"WWW-Authenticate": challenge}))

    """Handle an incoming request" let it through or reject it with a 401"""
    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        if "Authorization" in request.headers and self._verify_authorization(
            request.headers["Authorization"], request
            ):
            return self.next(conn_info, request)
        return self._unauthorized()

    """Parse and check a Digest Authorization header"""
    def _verify_authorization(self, header_value: str, request: HTTPRequest) -> bool:
        auth_type, _, data = header_value.partition(" ")
        if not data or auth_type != "Digest":
            return False

        try:
            params = parse_keqv_list(parse_http_list(data))
        except ValueError:
            LOG.warning("Invalid Digest authentication header")
            return False

        required_fields = ["username", "realm", "nonce", "uri", "response", "qop", "nc", "cnonce"]
        if not all(field in params for field in required_fields):
            LOG.warning("Missing required fields in Digest authentication header")
            return False

        username = params["username"]
        stored_hash = self.users.get(username)
        if not stored_hash:
            LOG.warning(f"Digest authentication: unknown user '{username}'")
            return False

        if params["realm"] != self.realm:
            LOG.warning("Digest authentication: realm mismatch")
            return False
        
        nonce = params["nonce"]
        issued_at = self.nonces.get(nonce)
        if issued_at is None:
            return False
        if time.time() - issued_at > NONCE_LIFETIME:
            del self.nonces[nonce]
            return False

        if params["qop"] != "auth":
            LOG.warning("Digest authentication: unsupported qop value")
            return False

        if params["uri"] != request.path:
            LOG.warning("Digest authentication: URI mismatch")
            return False

        ha1 = self._sha256(f"{username}:{self.realm}:{stored_hash}")

        ha2 = self._sha256(f"{request.method}:{params['uri']}")

        expected = self._sha256(
            f"{ha1}:{nonce}:{params['nc']}:{params['cnonce']}:{params['qop']}:{ha2}"
        )

        if hmac.compare_digest(expected.encode("utf-8"), params["response"].encode("utf-8")):
            LOG.debug("Digest authentication correct credentials.")
            return True

        LOG.warning("Digest authentication incorrect credentials.")
        return False
    
    @staticmethod
    def _sha256(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()







        

        

        