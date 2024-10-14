This is a project made for the purpose of learning the concepts like authentication, authorization, middleware to integrate in a web application.

**PRE-REQUISITES**
Python 3.10+
FastAPI

**CLONE THE REPOSITORY**
git clone <repository-url>
cd <repository-directory>

**CREATE ENVIRONMENT**
python3 -m venv env
source venv/bin/activate 

**INSTALL REQUIRED DEPENDENCIES**
pip install -r requirements.txt

**CONFIGURE THE SECRETS IN AN ENV FILE**
create a .env file and enter the secrets into it. Here you can add the following:
For jwt token:

SECRET_KEY = "<yoursecretkey>" 
ALGORITHM = "<algorithm>"  

For database credentials:

username = <username>
password = <password>
ip_address = <ip_address>
port = <port>
database = <database>

**Run the Application**
uvicorn main:app --reload

Access the Swagger UI by accessing the local host  and navigate to web browser.

**Project Structure**
main.py  - entry point to the fastapi application
requirements.txt - to install the required dependencies
auth.py - routes for the authentication handles
auth_utils.py - contains utilities needed for the authentication purposes
models.py - contains models for database structure
middleware.py - contains the middleware setup for the application.
