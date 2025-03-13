# flora-backend

## Setup Instructions
1. Clone the repository:
```sh
git clone <repo_url>
cd flask_project
```
2. Create and activate a virtual environment:
```sh
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```
3. Install dependencies:
```sh
pip install -r requirements.txt
```
4. Set up a PostgreSQL database and update `.env` file.
5. Run the application:
```sh
flask run
```
6. To push to GitHub:
```sh
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin <repo_url>
git push -u origin main
```

7. Run the application:
```sh
pip install flask-migrate flask-sqlalchemy psycopg2-binary python-dotenv
