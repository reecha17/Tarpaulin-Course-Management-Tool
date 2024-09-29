from flask import Flask, request, jsonify, send_file
from google.cloud import datastore

import requests
import json
import io

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
from google.cloud.datastore.query import PropertyFilter
from google.cloud import storage


app = Flask(__name__)
app.secret_key = "SECRET_KEY"

client = datastore.Client()

# Routing Constants
USERS = "users"
COURSES = "courses"
AVATAR = "avatar"
STUDENTS = "students"
PHOTO_BUCKET = "a6_photos_lerich"

# Entity Attributes
COURSE_ATTR = ["subject", "number", "title", "term", "instructor_id"]
COURSE_STUDENTS_ATTR = ["add", "remove"]

# Response Errors
FOUR_ZERO_ZERO = {"Error": "The request body is invalid"}, 400
FOUR_ZERO_ONE = {"Error": "Unauthorized"}, 401
FOUR_ZERO_THREE = {"Error": "You don't have permission on this resource"}, 403
FOUR_ZERO_FOUR = {"Error": "Not found"}, 404
FOUR_ZERO_NINE = {"Error": "Enrollment data is invalid"}, 409

# Update the values of the following 3 variables
CLIENT_ID = ""
CLIENT_SECRET = ""
DOMAIN = ""

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    "auth0",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        "scope": "openid profile email",
    },
)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if "Authorization" in request.headers:
        auth_header = request.headers["Authorization"].split()
        token = auth_header[1]
    else:
        raise AuthError(
            {
                "code": "no auth header",
                "description": "Authorization header is missing",
            },
            401,
        )

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Invalid header. "
                "Use an RS256 signed JWT Access Token",
            },
            401,
        )
    if unverified_header["alg"] == "HS256":
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Invalid header. "
                "Use an RS256 signed JWT Access Token",
            },
            401,
        )
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/",
            )
        except jwt.ExpiredSignatureError:
            raise AuthError(
                {"code": "token_expired", "description": "token is expired"}, 401
            )
        except jwt.JWTClaimsError:
            raise AuthError(
                {
                    "code": "invalid_claims",
                    "description": "incorrect claims,"
                    " please check the audience and issuer",
                },
                401,
            )
        except Exception:
            raise AuthError(
                {
                    "code": "invalid_header",
                    "description": "Unable to parse authentication" " token.",
                },
                401,
            )

        return payload
    else:
        raise AuthError(
            {"code": "no_rsa_key", "description": "No RSA key in JWKS"}, 401
        )


# error exceptions
class CredentialException(Exception):
    pass


@app.route("/")
def index():
    return "Hello!"


# Decode the JWT supplied in the Authorization header
@app.route("/decode", methods=["GET"])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# Image upload functions
def store_image(user_id):
    file_obj = request.files["file"]
    if "tag" in request.form:
        tag = request.form["tag"]
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(f"{user_id}.png")
    file_obj.seek(0)
    blob.upload_from_file(file_obj)


@app.route("/images/<file_name>", methods=["GET"])
def get_image(file_name):
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(file_name)
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)
    # Send the object as a file in the response with the correct MIME type and file name
    return send_file(file_obj, mimetype="image/png", download_name=file_name)


@app.route("/images/<file_name>", methods=["DELETE"])
def delete_image(file_name):
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(file_name)
    # Delete the file from Cloud Storage
    blob.delete()
    return "", 204


# User functions
@app.route(f"/{USERS}/login", methods=["POST"])
def login_user():
    try:
        content = request.get_json()
        username = content["username"]
        password = content["password"]
        body = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }
        headers = {"content-type": "application/json"}
        url = "https://" + DOMAIN + "/oauth/token"
        r = requests.post(url, json=body, headers=headers).json()
        if "error" in r:
            raise CredentialException
        return {"token": r["id_token"]}, 200
    except KeyError:
        return FOUR_ZERO_ZERO
    except CredentialException:
        return FOUR_ZERO_ONE


@app.route(f"/{USERS}", methods=["GET"])
def get_users():
    try:
        payload = verify_jwt(request)
        admin_query = client.query(kind=USERS)
        admin_query.add_filter(filter=PropertyFilter("sub", "=", payload["sub"]))
        results = list(admin_query.fetch())

        # invalid JWT or sub
        if not results:
            return FOUR_ZERO_ONE

        # invalid role
        admin = results[0]
        if admin["role"] != "admin":
            return FOUR_ZERO_THREE

        # return all users
        users_query = client.query(kind=USERS)
        results = list(users_query.fetch())
        for r in results:
            r["id"] = r.key.id
        return results, 200
    except AuthError:
        return FOUR_ZERO_ONE


@app.route(f"/{USERS}/<int:user_id>", methods=["GET"])
def get_user_id(user_id):
    try:
        payload = verify_jwt(request)
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)

        # user doesn't exist
        if user is None:
            return FOUR_ZERO_THREE

        # invalid role or user
        if user["sub"] != payload["sub"]:
            # query to check if admin
            user_query = client.query(kind=USERS)
            user_query.add_filter(filter=PropertyFilter("sub", "=", payload["sub"]))
            results = list(user_query.fetch())
            if not results:
                return FOUR_ZERO_THREE
            admin = results[0]
            if admin["role"] != "admin":
                return FOUR_ZERO_THREE

        # return user information
        r = {"id": user_id, "role": user["role"], "sub": user["sub"]}

        # get avatar url if exists
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        # Create a blob with the given file name
        if bucket.blob(f"{user_id}.png").exists():
            r["avatar_url"] = f"{request.url_root}{USERS}/{user_id}/{AVATAR}"

        # if instructor
        courses = []
        if user["role"] == "instructor":
            courses_query = client.query(kind=COURSES)
            courses_query.add_filter(
                filter=PropertyFilter("instructor_id", "=", user_id)
            )
            results = list(courses_query.fetch())
            for course in results:
                courses.append(f"{request.url_root}{COURSES}/{course.key.id}")
            r["courses"] = courses

        # if student
        if user["role"] == "student":
            courses_query = client.query(kind=COURSES)
            courses_query.add_filter("students", "IN", [user_id])
            results = list(courses_query.fetch())
            for course in results:
                print(course)
                courses.append(f"{request.url_root}{COURSES}/{course.key.id}")
            r["courses"] = courses

        return r, 200
    except AuthError:
        return FOUR_ZERO_ONE


# avatar functions
@app.route(f"/{USERS}/<int:user_id>/{AVATAR}", methods=["POST"])
def post_avatar(user_id):
    try:
        # 400 error handle
        if "file" not in request.files:
            return FOUR_ZERO_ZERO

        # 401 error handle
        payload = verify_jwt(request)

        # 403 error handle
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        if user is None:
            return FOUR_ZERO_THREE
        if payload["sub"] != user["sub"]:
            return FOUR_ZERO_THREE

        # store image
        store_image(user_id)

        r = {"avatar_url": f"{request.base_url}"}
        return r, 200
    except AuthError:
        return FOUR_ZERO_ONE


@app.route(f"/{USERS}/<int:user_id>/{AVATAR}", methods=["GET"])
def get_avatar(user_id):
    try:
        # 401 error handle
        payload = verify_jwt(request)

        # 403 error handle
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        if user is None:
            return FOUR_ZERO_THREE
        if payload["sub"] != user["sub"]:
            return FOUR_ZERO_THREE

        # 404 error handle
        # get avatar url if exists
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        if not bucket.blob(f"{user_id}.png").exists():
            return FOUR_ZERO_FOUR

        return get_image(f"{user_id}.png")
    except AuthError:
        return FOUR_ZERO_ONE


@app.route(f"/{USERS}/<int:user_id>/{AVATAR}", methods=["DELETE"])
def delete_avatar(user_id):
    try:
        # 401 error handle
        payload = verify_jwt(request)

        # 403 error handle
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        if user is None:
            return FOUR_ZERO_THREE
        if payload["sub"] != user["sub"]:
            return FOUR_ZERO_THREE

        # 404 error handle
        # get avatar url if exists
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(f"{user_id}.png")
        if not blob.exists():
            return FOUR_ZERO_FOUR
        else:
            blob.delete()

        return "", 204
    except AuthError:
        return FOUR_ZERO_ONE


# Course functions
@app.route(f"/{COURSES}", methods=["POST"])
def create_course():
    try:
        # 401 error handle
        payload = verify_jwt(request)

        content = request.get_json()

        # 400 error handle
        # check if required attributes exist
        for attr in COURSE_ATTR:
            if attr not in content:
                return FOUR_ZERO_ZERO

        # check if instructor id exists
        instructor_id = content["instructor_id"]
        instructor_key = client.key(USERS, instructor_id)
        instructor = client.get(key=instructor_key)
        if instructor is None or instructor["role"] != "instructor":
            return FOUR_ZERO_ZERO

        # 403 error handle
        admin_query = client.query(kind=USERS)
        admin_query.add_filter(filter=PropertyFilter("sub", "=", payload["sub"]))
        results = list(admin_query.fetch())
        # no matching JWT
        if not results:
            return FOUR_ZERO_THREE
        # invalid role
        admin = results[0]
        if admin["role"] != "admin":
            return FOUR_ZERO_THREE

        new_course = datastore.entity.Entity(key=client.key(COURSES))
        for attr in COURSE_ATTR:
            new_course.update({attr: content[attr]})
        new_course["students"] = []
        client.put(new_course)
        new_course["id"] = new_course.key.id
        new_course["self"] = f"{request.base_url}/{new_course.key.id}"
        del new_course["students"]
        return new_course, 201
    except AuthError:
        return FOUR_ZERO_ONE


@app.route(f"/{COURSES}", methods=["GET"])
def get_all_course():
    offset = request.args.get("offset", type=int)
    limit = request.args.get("limit", type=int)

    if offset is None:
        offset = 0
    if limit is None:
        limit = 3

    courses_query = client.query(kind=COURSES)
    courses_query.order = ["subject"]
    c_iterator = courses_query.fetch(limit=limit, offset=offset)
    pages = c_iterator.pages
    courses = list(next(pages))
    for course in courses:
        course["id"] = course.key.id
        course["self"] = f"{request.root_url}{COURSES}/{course.key.id}"
        del course["students"]

    offset += 3
    results = {
        COURSES: courses,
        "next": f"{request.url_root}{COURSES}?limit={limit}&offset={offset}",
    }
    return results, 200


@app.route(f"/{COURSES}/<int:course_id>", methods=["GET"])
def get_course(course_id):
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)

    # Handle 404 Error
    if course is None:
        return FOUR_ZERO_FOUR

    course["id"] = course_id
    course["self"] = f"{request.base_url}"
    del course["students"]

    return course, 200


@app.route(f"/{COURSES}/<int:course_id>", methods=["PATCH"])
def update_course(course_id):
    try:
        # Handle 400 Error
        content = request.get_json()
        if "instructor_id" in content:
            # check if instructor id exists
            instructor_id = content["instructor_id"]
            instructor_key = client.key(USERS, instructor_id)
            instructor = client.get(key=instructor_key)
            if instructor is None or instructor["role"] != "instructor":
                return FOUR_ZERO_ZERO

        # Handle 401 Error
        payload = verify_jwt(request)

        # Handle 403 Error
        # Get course info
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        # Get Admin info
        admin_query = client.query(kind=USERS)
        admin_query.add_filter(filter=PropertyFilter("sub", "=", payload["sub"]))
        results = list(admin_query.fetch())
        # no matching JWT
        if not results:
            return FOUR_ZERO_THREE
        # course doesn't exist or invalid role
        admin = results[0]
        if course is None or admin["role"] != "admin":
            return FOUR_ZERO_THREE

        # update course
        for attr in content:
            course[attr] = content[attr]
        client.put(course)

        # return with id and self values
        course["id"] = course_id
        course["self"] = f"{request.base_url}"
        return course, 200
    except AuthError:
        return FOUR_ZERO_ONE


@app.route(f"/{COURSES}/<int:course_id>", methods=["DELETE"])
def delete_course(course_id):
    try:
        # Handle 401 Error
        payload = verify_jwt(request)

        # Handle 403 Error
        # Get course info
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        # Get Admin info
        admin_query = client.query(kind=USERS)
        admin_query.add_filter(filter=PropertyFilter("sub", "=", payload["sub"]))
        results = list(admin_query.fetch())
        # no matching JWT
        if not results:
            return FOUR_ZERO_THREE
        # course doesn't exist or invalid role
        admin = results[0]
        if course is None or admin["role"] != "admin":
            return FOUR_ZERO_THREE

        # Delete Course
        client.delete(course_key)

        return "", 204
    except AuthError:
        return FOUR_ZERO_ONE


@app.route(f"/{COURSES}/<int:course_id>/{STUDENTS}", methods=["PATCH"])
def update_course_students(course_id):
    try:
        content = request.get_json()

        # Handle 401 Error
        payload = verify_jwt(request)

        # Handle 403 Error
        # Get course info
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        # Get Admin info
        admin_query = client.query(kind=USERS)
        admin_query.add_filter(filter=PropertyFilter("sub", "=", payload["sub"]))
        results = list(admin_query.fetch())
        # no matching JWT
        if not results:
            return FOUR_ZERO_THREE
        # course doesn't exist or invalid role
        admin = results[0]
        if course is None or admin["role"] != "admin":
            return FOUR_ZERO_THREE

        # Handle 409 Error: common value between "add" and "remove"
        if set(content["add"]) == set(content["remove"]):
            raise KeyError

        enrollment_list = course["students"]
        # Add students
        for student_id in content["add"]:
            student_key = client.key(USERS, student_id)
            student = client.get(key=student_key)
            # 409 Error: student doesn't exist or user_id is not a student
            if student is None or student["role"] != "student":
                raise KeyError
            if student_id not in enrollment_list:
                enrollment_list.append(student_id)

        # Remove students
        for student_id in content["remove"]:
            student_key = client.key(USERS, student_id)
            student = client.get(key=student_key)
            # 409 Error: student doesn't exist or user_id is not a student
            if student is None or student["role"] != "student":
                raise KeyError
            if student_id in enrollment_list:
                enrollment_list.remove(student_id)

        # update course with new enrollment list
        course["students"] = enrollment_list
        client.put(course)
        return "", 200

    except AuthError:
        return FOUR_ZERO_ONE

    except KeyError:
        return FOUR_ZERO_NINE


@app.route(f"/{COURSES}/<int:course_id>/{STUDENTS}", methods=["GET"])
def get_course_students(course_id):
    try:
        # Handle 401 Error
        payload = verify_jwt(request)

        # Handle 403 Error
        # course doesn't exist
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        if course is None:
            return FOUR_ZERO_THREE
        # not and instructor or admin
        instructor_id = course["instructor_id"]
        instructor_key = client.key(USERS, instructor_id)
        instructor = client.get(key=instructor_key)
        if instructor["sub"] != payload["sub"]:
            # Get Admin info
            admin_query = client.query(kind=USERS)
            admin_query.add_filter(filter=PropertyFilter("sub", "=", payload["sub"]))
            results = list(admin_query.fetch())
            # JWT doesn't exist in database
            if not results:
                return FOUR_ZERO_THREE
            # JWT doesn't belong to admin
            admin = results[0]
            if course is None or admin["role"] != "admin":
                return FOUR_ZERO_THREE

        return course["students"], 200
    except AuthError:
        return FOUR_ZERO_ONE


# Create a lodging if the Authorization header contains a valid JWT
""" @app.route("/lodgings", methods=["POST"])
def lodgings_post():
    if request.method == "POST":
        payload = verify_jwt(request)
        content = request.get_json()
        new_lodging = datastore.entity.Entity(key=client.key(LODGINGS))
        new_lodging.update(
            {
                "name": content["name"],
                "description": content["description"],
                "price": content["price"],
            }
        )
        client.put(new_lodging)
        return jsonify(id=new_lodging.key.id)
    else:
        return jsonify(error="Method not recogonized") """


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
