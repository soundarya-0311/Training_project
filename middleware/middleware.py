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
            # Skip authentication for publicly accessible paths
            if request.url.path in ["/docs", "/openapi.json", "/favicon.ico", "/auth/login", "/auth/user_register"]:
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

logging.basicConfig(filename='info.log', level = logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def log_info(req_body, res_body, method, url,path):
    logging.info(req_body)
    logging.info(res_body)
    logging.info(method)
    logging.info(path)
    logging.info(url)
    
    
@app.middleware('http')
async def log_middleware(request: Request, call_next):
    req_body = await request.body()
    method = request.method
    path = request.url.path
    url = request.url
    response = await call_next(request)
    res_body = b''
    async for chunk in response.body_iterator:
        res_body += chunk
    background_task = BackgroundTasks()
    background_task.add_task(log_info,req_body.decode('utf-8'), res_body.decode('utf-8'), method,path,url)
    return Response(content = res_body, status_code = response.status_code,
                    headers = dict(response.headers), media_type = response.media_type, background = background_task)

#Structure for rbac
Roles = {
    "admin" : ["/services/check_user_details","/services/view_user_data", "/services/view_specific_user", "/services/delete_user_details", "/services/edit_user_details", "/services/search_users", "/services/filter_users", "/services/user_reports",
               "/services/report_csv"],
    "user" : ["/services/view_user_data", "/services/delete_user_details", "/services/edit_user_details", "/services/search_users"]
}

def grant_access(user_role, required_permission):
    user_role = user_role.lower()
    if user_role in Roles and required_permission in Roles[user_role]:
        return True
    return False


class RBACMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        try:               
            if request.url.path in ["/docs", "/openapi.json", "/favicon.ico", "/auth/login", "/auth/user_register", "/auth/logout"]:
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
app.add_middleware(CustomMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Set the allowed origins here (e.g., ["http://localhost", "https://example.com"])
    allow_credentials=True,
    allow_methods=["*"],  # Set the allowed HTTP methods here (e.g., ["GET", "POST"])
    allow_headers=["*"],
)
