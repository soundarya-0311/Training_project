import traceback
from fastapi import APIRouter,Depends,HTTPException,status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import Users, Tokens
from schemas.schemas import RegisterCredentials
from utilities.auth_utils import get_hashed_password,verify_password,create_access_token,create_refresh_token,get_current_user

router = APIRouter()

@router.post("/user_register")
def user_registeration(user: RegisterCredentials, db: Session = Depends(get_db)):
    try:
        existing_user = db.query(Users).filter(Users.email == user.email, Users.is_active == True).first()
        if existing_user:
            raise HTTPException(status_code = status.HTTP_400_BAD_REQUEST, detail = "Email Already Registered")
        
        hash_password = get_hashed_password(user.password) #Hashing pasword before adding new user to database
        
        new_user = Users(username = user.username, email = user.email, hashed_password = hash_password) #Adding to db
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
        
        access_token = create_access_token(data = {"sub": user.username})
        refresh_token = create_refresh_token(data = {"sub" : user.username})
        
        tokentable = Tokens(user_id = user.id, access_token = access_token, refresh_token = refresh_token)
        db.add(tokentable)
        db.commit()
        
        return JSONResponse(
            status_code = status.HTTP_200_OK,
            content = {"message" : "LoggedIn Successfully"}
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
        
@router.get("/check_current_user")
def check_current_user(user = Depends(get_current_user)):
    return {"current_user" : user}

@router.post('/logout')
def logout(user_id : int , db: Session = Depends(get_db)):
    try:
        existing_token = db.query(Tokens).filter(Tokens.user_id == user_id, Tokens.is_active == True).delete()
        if not existing_token:
            raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "No Access found for the user")
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