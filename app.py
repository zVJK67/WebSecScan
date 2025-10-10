from flask import Flask, make_response

app = Flask(__name__)

@app.route('/')
def index():
    resp = make_response("Hello from local test server!")
    # Example: cookie without Secure/HttpOnly/SameSite → shows as unsafe
    resp.set_cookie('test_cookie', '12345', secure=False, httponly=False)
    return resp

if __name__ == '__main__':
    app.run(port=5000)
