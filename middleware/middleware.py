from fastapi import HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from utilities.auth_utils import verify_token,RoleChecker
from main import app

class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Skip authentication for publicly accessible paths
        if request.url.path in ["/docs", "/openapi.json", "/favicon.ico", "/login", "/user_register"]:
            return await call_next(request)
        token = request.headers.get("Authorization")
        if token and token.startswith("Bearer"):
            token = token.split(" ")[1]
        if not token or not verify_token(token):
            raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail = "Unauthorized")
        response = await call_next(request)
        return response

class RoleBasedAccess(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path in ["/docs", "/openapi.json", "/favicon.ico", "/login", "/user_register"]:
            return await call_next(request)
        if RoleChecker(["ADMIN"]):
            return await call_next(request)       
        
app.add_middleware(RoleBasedAccess)
app.add_middleware(AuthenticationMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Set the allowed origins here (e.g., ["http://localhost", "https://example.com"])
    allow_credentials=True,
    allow_methods=["*"],  # Set the allowed HTTP methods here (e.g., ["GET", "POST"])
    allow_headers=["*"],
)
