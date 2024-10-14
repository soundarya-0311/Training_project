from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from utilities.auth_utils import verify_token
from main import app

class CustomMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        try:
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
        except HTTPException as e:
            return JSONResponse(
                status_code = e.status_code,
                content = e.detail
            )
        except Exception:
            return JSONResponse(
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
                content = {"message" : "Something went wrong"}
            )


app.add_middleware(CustomMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Set the allowed origins here (e.g., ["http://localhost", "https://example.com"])
    allow_credentials=True,
    allow_methods=["*"],  # Set the allowed HTTP methods here (e.g., ["GET", "POST"])
    allow_headers=["*"],
)
