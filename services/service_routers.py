import traceback
import io
from datetime import datetime, timezone, timedelta
import pandas as pd
from fastapi import APIRouter,Depends,HTTPException,status
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi_pagination import Page 
from fastapi_pagination.ext.sqlalchemy import paginate
from sqlalchemy import distinct
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import Users, JWT_Tokens
from schemas.schemas import EditUserDetails, SearchUsers, UserResponseSchema
from utilities.auth_utils import get_hashed_password,get_current_user,RoleChecker

router = APIRouter(
    tags=["Services"],
    prefix = "/services"
)

@router.get("/check_user_details")
def check_all_users(allowed_role : bool = Depends(RoleChecker(["ADMIN"]))):
    try:
        if not allowed_role:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Access Denied")
        
        return JSONResponse(
                status_code = status.HTTP_200_OK,
                content = {"message" : "Admin Access Provided"})
            
    except HTTPException as e:
        traceback.print_exc()
        return JSONResponse(
            status_code=e.status_code,
            content = e.detail
        )
    except Exception:
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something Went Wrong"}
        ) 

@router.get("/view_user_data", response_model = Page[UserResponseSchema])
def view_user_data(user = Depends(get_current_user), db: Session = Depends(get_db)) -> Page[UserResponseSchema]:
    try:
        """This API is to view all details of all users which can be done only by admin. 
            If other user tries to view they can only view their details. Pagination is implemented to limit the 
            amount of records to be viewed per page"""
        if user.role.value == "ADMIN":
            user_query = db.query(Users).filter(Users.is_active == True)
        else:
            user_query = db.query(Users).filter(Users.username == user.username, Users.is_active == True)
        
        return paginate(user_query)            
    
    except Exception:
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something Went Wrong"}
        )

@router.post("/view_specific_user")
def view_specific_user(user_id: int, user = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        """This API used to view details of specific user and this is an admin only accessible route"""
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
        """This API is to delete the specific user from database.
        Only Admin can delete any user's detail. Others can only delete theirs"""
        if user.role.value == "ADMIN" or user_id == user.id:
            user_query = db.query(Users).filter(Users.id == user_id, Users.is_active == True).first()
            if not user_query:
                raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "User Not Found")
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

@router.put("/edit_user_details")
def edit_user_details(update_details: EditUserDetails, user_id : int, current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        """To Edit details of a User.
        -Admins can update details of any user
        - Regular users can update only theirs."""
        if current_user.role.value == "ADMIN" or user_id == current_user.id:
            user_details = db.query(Users).filter(Users.id == user_id, Users.is_active == True).first()
        else:
            raise HTTPException(status_code = status.HTTP_400_BAD_REQUEST, detail = "You are not allowed to update other users details") 
        
        if not user_details:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail = "User Not Found or Inactive")
        
        if update_details.email:
            user_details.email = update_details.email
        if update_details.username:
            user_details.username = update_details.username
        if update_details.password:
            user_details.hashed_password= get_hashed_password(update_details.password)
        
        db.add(user_details)
        db.commit()
        
        return JSONResponse(
            status_code = status.HTTP_200_OK,
            content = {"message" : "Successfully Updated"}
        )
    
    except HTTPException as e:
        db.rollback()
        traceback.print_exc()
        return JSONResponse(
            status_code=e.status_code,
            content = e.detail
        )
    
    except Exception:
        db.rollback()
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something Went Wrong"}
        )
            
@router.post("/search_users")
def search_users(search_details: SearchUsers, current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        """Basic Search API. This Api is common for both admin and users to search and retrieve the details of user based on their name or role"""
        if search_details.username and search_details.role:
            search_users_query = db.query(Users).filter(Users.username == search_details.username, Users.role == search_details.role.upper(), Users.is_active == True).all()
        elif search_details.username:
            search_users_query = db.query(Users).filter(Users.username == search_details.username, Users.is_active == True).all()
        elif search_details.role:
            search_users_query = db.query(Users).filter(Users.role == search_details.role.upper(), Users.is_active == True).all()
        else:
            raise HTTPException(status_code = status.HTTP_400_BAD_REQUEST, detail = "Enter username or role to proceed")
        
        if not search_users_query:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Invalid Username or role.")
        
        return search_users_query
    
    except HTTPException as e:
        traceback.print_exc()
        return JSONResponse(
            status_code=e.status_code,
            content = e.detail
        )
    except Exception:
        traceback.print_exc()
        return JSONResponse(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something went wrong"}
        )

@router.post("/filter_users")
def filter_users(user_status: bool, current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        """This Api is and admin only accessible API used to filter the users based on their status
           user_status - Active/InActive in boolean.
           Active - loggedin Users.
           Inactive - loggedout Users. 
           Based on recent activity here last 30 minutes activity"""
        recent_update = datetime.now(timezone.utc) - timedelta(minutes = 30) 
        track_status_query = db.query(Users).join(JWT_Tokens, Users.id == JWT_Tokens.user_id).\
                             filter(JWT_Tokens.is_active == user_status, JWT_Tokens.updated_ts >= recent_update).all()
        if not track_status_query:
            raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "No Recent User Activity Found")
        
        return track_status_query
    
    except HTTPException as e:
        traceback.print_exc()
        return JSONResponse(
        status_code= e.status_code,
        content = e.detail
    )
        
    except Exception:
        traceback.print_exc()
        return JSONResponse(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message":"Something Went Wrong"}
        )

@router.get("/user_reports")
def user_reports(current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        """This is an Admin only Accessible route which is used to generate basic user reports.
           Count of recent registrations, active users, total users available.
           Recent registrations will be based on users registered in a week from the time of hitting the api. 
           Active users based on last 30 minutes of activity."""
        total_users = db.query(Users).filter(Users.is_active == True).count()
        
        recent_registration_time = datetime.now(timezone.utc) - timedelta(days = 7)
        recent_registrations = db.query(Users).filter(Users.created_ts >= recent_registration_time, Users.is_active == True).count()
        
        active_users_recent = datetime.now(timezone.utc) - timedelta(minutes = 30)
        active_users = db.query(distinct(Users.id)).join(JWT_Tokens, Users.id == JWT_Tokens.user_id).\
            filter(JWT_Tokens.is_active == True, JWT_Tokens.updated_ts >= active_users_recent).count()
        
        report = {
            "total_users" :  total_users,
            "recent_registrations" : recent_registrations,
            "currently_active_users" : active_users 
        }
        
        return report
    
    except Exception:
        traceback.print_exc()
        return JSONResponse(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something went wrong"}
        )

@router.get("/report_csv")
def user_report_csv(current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        """Admin only accessible route which is used to generate reports as well as to save locally as a CSV file."""
        user_query = db.query(Users).filter(Users.is_active == True).all()
                
        # Serialize user data into a list of dictionaries
        users_data = [
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role.value
            }
            for user in user_query
        ]
                
        total_users = db.query(Users).filter(Users.is_active == True).count()
        
        recent_registration_time = datetime.now(timezone.utc) - timedelta(days = 7)
        recent_registrations = db.query(Users).filter(Users.created_ts >= recent_registration_time, Users.is_active == True).count()
        
        active_users_recent = datetime.now(timezone.utc) - timedelta(minutes = 30)
        active_users = db.query(distinct(Users.id)).join(JWT_Tokens, Users.id == JWT_Tokens.user_id).\
            filter(JWT_Tokens.is_active == True, JWT_Tokens.updated_ts >= active_users_recent).count()
        
        summary_data = {
            "Total Users" : [total_users],
            "Recent Registrations (last 7 days)" : [recent_registrations],
            "Currently Active Users (last 30 minutes)" : [active_users]
        }
        
        report_df = pd.DataFrame(summary_data)
        users_df = pd.DataFrame(users_data)
        user_report_df = pd.concat([report_df, users_df], axis = 1)
        
        output = io.StringIO() #to create an in memory temporary file.
        user_report_df.to_csv(output, index = False)
        
        return StreamingResponse(iter([output.getvalue()]),headers = {"Content-Disposition" : "attachment; filename = user_reports.csv"}, media_type = "text/csv")
        
        
    except Exception:
        traceback.print_exc()
        return JSONResponse(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            content = {"message" : "Something Went Wrong"}
        )
        