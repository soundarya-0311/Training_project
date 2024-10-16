import logging
import traceback
from fastapi import HTTPException, status, Response,Request, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from utilities.auth_utils import verify_token
from main import app
class CustomMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        try:
            if request.url: #To skip error during redirection to swagger
                return await call_next(request)
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
            traceback.print_exc()
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

logging.basicConfig(filename='info.log', level = logging.DEBUG)

def log_info(req_body, res_body):
    logging.info(req_body)
    logging.info(res_body)
    
@app.middleware('http')
async def log_middleware(request: Request, call_next):
    req_body = await request.body()
    response = await call_next(request)
    res_body = b''
    async for chunk in response.body_iterator:
        res_body += chunk
    background_task = BackgroundTasks()
    background_task.add_task(log_info,req_body.decode('utf-8'), res_body.decode('utf-8'))
    return Response(content = res_body, status_code = response.status_code,
                    headers = dict(response.headers), media_type = response.media_type, background = background_task)

#Structure for rbac
Roles = {
    "admin" : ["/check_user_details","/view_user_data", "/view_specific_user", "/delete_user_details", "/edit_user_details", "/search_users"],
    "user" : ["/view_user_data", "/delete_user_details", "/edit_user_details", "/search_users"]
}

def grant_access(user_role, required_permission):
    user_role = user_role.lower()
    if user_role in Roles and required_permission in Roles[user_role]:
        return True
    return False


class RBACMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        try:
            if request.url:
                return await call_next(request)                
            if request.url.path in ["/docs", "/openapi.json", "/favicon.ico", "/login", "/user_register"]:
                    return await call_next(request)
            token = request.headers.get("Authorization")
            if token and token.startswith("Bearer"):
                token = token.split(" ")[1]
            role = verify_token(token)[1]
            if not grant_access(role, request.url.path):
                raise HTTPException(status_code = status.HTTP_403_FORBIDDEN, detail = "Access Denied")
            response = await call_next(request)
            return response
        
        except HTTPException as e:
            return JSONResponse(
                status_code = e.status_code,
                content = e.detail
            )
        
        except Exception:
            traceback.print_exc()
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content = "Something Went Wrong"
            )

app.add_middleware(RBACMiddleware)