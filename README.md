# Training project

This is a project made for the purpose of learning the concepts like authentication, authorization, middleware to integrate in a web application.

## SET-UP Instructions

### PRE-REQUISITES
- Python 3.10+
- FastAPI

### Installation

**1.CLONE THE REPOSITORY**
```bash
git clone <repository-url>
cd <repository-directory>
```

**2.CREATE ENVIRONMENT**
```bash
python3 -m venv env
source venv/bin/activate
```

**3.INSTALL REQUIRED DEPENDENCIES**
```bash
pip install -r requirements.txt
```

### Configuration

Create a '.env' file and enter the secrets into it. Here you can add the following:
For jwt token:
```plaintext
SECRET_KEY = "yoursecretkey" 
ALGORITHM = "algorithm"  
```
For database credentials:
```plaintext
username = <username>
password = <password>
ip_address = <ip_address>
port = <port>
database = <database>
```
### Run the Application

```bash
uvicorn main:app --reload
```
Access the Swagger UI by accessing the local host  and navigate to web browser.

### Project Structure

- **main.py**  - entry point to the fastapi application
- **requirements.txt** - to install the required dependencies
- **auth.py** - routes for the authentication handles
- **services** - routes to handle services
- **auth_utils.py** - contains utilities needed for the authentication purposes
- **models.py** - contains models for database structure
- **middleware.py** - contains the middleware setup for the application.
- **schemas.py** - contains response and request body structure that can be used as payloads.
