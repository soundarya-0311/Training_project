import traceback
from fastapi import APIRouter,Depends,HTTPException,status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import Users, JWT_Tokens
from schemas.schemas import RegisterCredentials, rolename
from utilities.auth_utils import get_hashed_password,verify_password,create_access_token,create_refresh_token,get_current_user,oauth2_scheme,RoleChecker

router = APIRouter()

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
def login(formdata: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
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
        
        tokentable = JWT_Tokens(user_id = user.id, access_token = access_token, refresh_token = refresh_token)
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
        
@router.get("/check_user_details")
def check_all_users(allowed_role : bool = Depends(RoleChecker(["ADMIN"]))):
    return "Admin Access Provided" if allowed_role else "Access Denied."

@router.get("/view_user_data")
def view_user_data(user = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        if user.role.value == "ADMIN":
            user_query = db.query(Users).filter(Users.is_active == True).all()
        else:
            user_query = db.query(Users).filter(Users.username == user.username, Users.is_active == True).first()
        
        return user_query
    
    except Exception:
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something Went Wrong"}
        )

@router.post("/view_specific_user")
def write_access(user_id: int, user = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        user_query = db.query(Users).filter(Users.id == user_id,Users.is_active == True).first()
        return user_query
    except Exception:
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something Went Wrong"}
        )

@router.delete("/delete_user_details")
def delete_details(user_id: int, user = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        if user.role.value == "ADMIN":
            user_query = db.query(Users).filter(Users.id == user_id, Users.is_active == True).first()
            if not user_query:
                raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "User Not Found")
            user_query.is_active = False
        else:
            if user.id == user_id:
                user_query = db.query(Users).filter(Users.id == user_id, Users.is_active == True).first()
                user_query.is_active = False  
            else:
                raise HTTPException(status_code = status.HTTP_400_BAD_REQUEST, detail = "You are not allowed to delete other users details") 
        
        db.add(user_query)
        db.commit()
        
        return JSONResponse(
            status_code = status.HTTP_200_OK,
            content = {"message" : "Successfully Deleted the Account", "deleted_id": user_query.id}
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
            content = {"message" : "Something went wrong"}
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