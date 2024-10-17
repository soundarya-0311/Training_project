import traceback
from typing import List
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter,Depends,HTTPException,status,Request
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session, joinedload
from database.database import get_db
from database.models import Users, JWT_Tokens
from schemas.schemas import RegisterCredentials, rolename
from utilities.auth_utils import get_hashed_password,verify_password,create_access_token,create_refresh_token,get_current_user,oauth2_scheme,REFRESH_TOKEN_EXPIRE_MINUTES

router = APIRouter(
    tags=["Authentication and Authorization"],
    prefix = "/auth"
)

@router.post("/user_register")
def user_registeration(user: RegisterCredentials, role: rolename, db: Session = Depends(get_db)):
    try:
        existing_mail = db.query(Users).filter(Users.email == user.email, Users.is_active == True).first()
        if existing_mail:
            raise HTTPException(status_code = status.HTTP_400_BAD_REQUEST, detail = "Email Already Registered")
        
        existing_username = db.query(Users).filter(Users.username == user.username, Users.is_active == True).first()
        if existing_username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Username Already Registered")
        
        hash_password = get_hashed_password(user.password) #Hashing pasword before adding new user to database
        
        new_user = Users(username = user.username, email = user.email, hashed_password = hash_password, role = role) #Adding to db
        db.add(new_user)
        db.commit()
        
        
        return JSONResponse(
            status_code = status.HTTP_200_OK,
            content = {"message" : "User Registered Successfully", "user_id" : new_user.id}
        )
    
    except HTTPException as e:
        db.rollback()
        traceback.print_exc()
        return JSONResponse(
            status_code = e.status_code,
            content = e.detail
        ) 
    
    except Exception:
        db.rollback()
        traceback.print_exc()
        return JSONResponse(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something Went Wrong"}
        )
        
@router.post('/login')
def login(request: Request,formdata: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
        user = db.query(Users).filter(Users.username == formdata.username, Users.is_active == True).first()
        if not user or not verify_password(formdata.password, user.hashed_password):
            raise HTTPException(
                status_code = status.HTTP_401_UNAUTHORIZED,
                detail = "Incorrect Username or Password",
                headers = {"WWW-Authenticate" : "Bearer"}
            )
        
        access_token = create_access_token(data = {"sub": user.username, "role" : str(user.role.value)})
        refresh_token = create_refresh_token(data = {"sub" : user.username, "role" : str(user.role.value)})
        
        #Capture device_info and IP_address for session management for security purposes
        device_info = request.headers.get("User-Agent", "Unknown Device")
        ip_address = request.client.host
        
        tokentable = JWT_Tokens(user_id = user.id, 
                                access_token = access_token, 
                                refresh_token = refresh_token, 
                                refresh_token_expiration = datetime.now(timezone.utc) + timedelta(minutes = REFRESH_TOKEN_EXPIRE_MINUTES),
                                device_info = device_info,
                                ip_address = ip_address,
                                last_activity = datetime.now(timezone.utc))
        db.add(tokentable)
        db.commit()
        
        return JSONResponse(
            status_code = status.HTTP_200_OK,
            content = {"message" : "LoggedIn Successfully", "access_token" : access_token, "token_type" : "Bearer"}
        )
    
    except HTTPException as e:
        db.rollback()
        traceback.print_exc()
        return JSONResponse(
            status_code = e.status_code,
            content = e.detail
        )
    
    except Exception:
        db.rollback()
        traceback.print_exc()
        return JSONResponse(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something Went Wrong"}
        )

@router.post('/logout')
def logout(user = Depends(get_current_user) , token = Depends(oauth2_scheme),db: Session = Depends(get_db)):
    try:
        existing_token = db.query(JWT_Tokens).filter(JWT_Tokens.user_id == user.id, JWT_Tokens.access_token == token,JWT_Tokens.is_active == True).first()
        if not existing_token:
            raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "No Access found for the user")
        existing_token.is_active = False
        db.add(existing_token)
        db.commit()
        
        return JSONResponse(
            status_code = status.HTTP_200_OK,
            content = {"message" : "Logged out Successfully"}
        )
    
    except HTTPException as e:
        db.rollback()
        traceback.print_exc()
        return JSONResponse(
            status_code = e.status_code,
            content = e.detail
        )
    
    except Exception:
        db.rollback()
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something Went Wrong"}
        )

@router.post("/refresh_token")
def refresh_token(refresh_token: str, db: Session = Depends(get_db)):
    try:
        """This API is to generate new access token using refresh token.
           Whenever user logs in access token and refresh token will be created where access token will have short 
           expiration time and refresh token will have long expiration time.This is to prevent user login frequently. 
           If an access token gets expired instead of logging in again, frontend will pass the corresponding refresh 
           token to this endpoint and this endpoint will check whether the refresh token is valid and not expired and 
           if so it will automatically generate a new access token and pass so user can continue using without logging in again.
           Advantages : To prevent frequent logins, To make the web/app highly secured as we can invalidate the session 
           whenever any suscpicious activity is sensed.
           Flow of the usage:
            1. **Login**:
                - User → Logs in → Receives access token and refresh token from backend.
            2. **API Request**:
                - User → Makes request with access token → Backend validates token.

            3. **Token Expiration**:
                - User → Access token expires → Frontend detects expiration.

            4. **Refresh Token Request**:
                - Frontend → Sends refresh token to refresh endpoint → Backend verifies refresh token.

            5. **New Tokens**:
                - Backend → Issues new access token (and possibly a new refresh token) → Frontend updates stored tokens."""
                
        refresh_token_query = db.query(JWT_Tokens).options(joinedload(JWT_Tokens.user)).\
            filter(JWT_Tokens.refresh_token == refresh_token, JWT_Tokens.is_active == True).first()
        if not refresh_token_query:
            raise HTTPException(status_code = status.HTTP_403_FORBIDDEN, detail = "Refresh Token not valid.")
        
        if refresh_token_query.refresh_token_expiration < datetime.now(timezone.utc):
            raise HTTPException(status_code = status.HTTP_403_FORBIDDEN, detail = "Refresh Token Expired. Login Again.")
       
        
        new_access_token = create_access_token(data = {"sub": refresh_token_query.user.username, "role" : str(refresh_token_query.user.role.value)})
        
        new_access_token_record = JWT_Tokens(
            user_id = refresh_token_query.user_id,
            access_token = new_access_token,
            refresh_token = refresh_token_query.refresh_token,
            refresh_token_expiration = refresh_token_query.refresh_token_expiration
        )
        
        db.add(new_access_token_record)
        db.commit()
        
        return JSONResponse(
            status_code = status.HTTP_200_OK,
            content = {"access_token" : new_access_token, "token_type" :  "Bearer"}
        )
    
    except HTTPException as e:
        db.rollback()
        traceback.print_exc()
        return JSONResponse(
            status_code = e.status_code,
            content = e.detail
        )
    
    except Exception:
        db.rollback()
        traceback.print_exc()
        return JSONResponse(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something Went Wrong"}
        )

@router.get("/active_session")
def get_active_sessions(current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        """This API will allow users to check their active session to check whether their account is in good status and not hacked.
           Eg. In google we will have an option to view our current sessions to know whether any new unknown logins are there to
           logout from that device and secure our account. This api is that kind of one where users can view their loggedin sessions/devices."""
        
        active_sessions = db.query(JWT_Tokens).filter(JWT_Tokens.user_id == current_user.id, JWT_Tokens.is_active == True).all()
        
        if not active_sessions:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "No Active Sessions so far.")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"active_sessions": [
                {"id": session.id,
                 "device_info": session.device_info, 
                 "ip_address": session.ip_address, 
                 "last_activity": session.last_activity.isoformat()} for session in active_sessions]
            }
        )
        
    except HTTPException as e:
        traceback.print_exc()
        return JSONResponse(
            status_code = e.status_code,
            content = e.detail
        )
    
    except Exception:
        traceback.print_exc()
        return JSONResponse(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something Went Wrong"}
        )

@router.post("/logout_other_devices")
def logout_other_devices(session_ids: List[int], current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        """This API allows users to logout from other or unknown devices after checking active sessions."""
        existing_sessions = db.query(JWT_Tokens).filter(JWT_Tokens.user_id == current_user.id, JWT_Tokens.id.in_(session_ids), JWT_Tokens.is_active == True).all()
        if not existing_sessions:
            raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "No sessions available")
        
        for session in existing_sessions:
            session.is_active = False
            db.add(session)
        
        db.commit()
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Logged out from other devices successfully."}
        )
    
    except HTTPException as e:
        traceback.print_exc()
        return JSONResponse(
            status_code = e.status_code,
            content = e.detail
        )
    
    except Exception:
        traceback.print_exc()
        return JSONResponse(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something Went Wrong"}
        )