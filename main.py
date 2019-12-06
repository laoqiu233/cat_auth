from flask import Flask, request, jsonify, make_response, render_template, redirect
from models import UserModel, jwtBlackList
from __init__ import app, db, secret
import time, re, jwt

db.create_all()

@app.route('/auth/')
def test():
    return "cat"

@app.route('/auth/test', methods=['GET'])
def test_view():
    if request.cookies.get('jwt'):
        return '''<p>{}</p>
                  <a href="/auth/api/logout?callback=/auth/test"><h1>Logout</h1></a>'''.format(request.cookies.get('jwt'))
    else:
        return '''<a href="/auth/register?callback=/auth/test"><h1>Sign-up</h1></a>
                  <a href="/auth/login?callback=/auth/test"><h1>Login</h1></a>'''

@app.route('/auth/api/token', methods=['GET'])
def check_token():
    """Should be only called from backend to backend"""
    data = request.args
    if 'jwt' not in data:
        return jsonify({'Message': 'Unauthorized'}), 401
    
    try:
        token = jwt.decode(data['jwt'], secret)
        user = UserModel.query.filter(UserModel.id==token['sub']).first()
        return jsonify({'Id': user.id, 'Username': user.username})
    except jwt.ExpiredSignatureError:
        return jsonify({'Expired': True}), 401
    except:
        return jsonify({'Invalid': True}), 401

@app.route('/auth/login', methods=['GET'])
def login_view():
    data = request.args
    response = render_template('login.html', callback=data['callback'])
    # Check if the user has already logged in
    token = request.cookies.get('jwt')
    if token:
        try:
            # Redirect user if logged in
            jwt.decode(token, secret)
            return redirect(data['callback'] + '?jwt=' + token)
        except jwt.ExpiredSignatureError:
            # Delete the token if it's expired
            response.delete_cookie('jwt')
    return response

@app.route('/auth/register', methods=['GET'])
def register_view():
    data = request.args
    response = render_template('register.html', callback=data['callback'])
    # Check if the user has already logged in
    token = request.cookies.get('jwt')
    if token:
        try:
            # Redirect user if logged in
            jwt.decode(token, secret)
            return redirect(data['callback'] + '?jwt=' + token)
        except jwt.ExpiredSignatureError:
            # Delete the token if it's expired
            response.delete_cookie('jwt')
    return response

@app.route('/auth/api/login', methods=['POST'])
def login():
    """Returns a jwt token based on the user credentials"""
    if request.method == 'POST':
        data = request.values

        # Check if no arguments are missing
        try:
            assert 'Username' in data
            assert 'Password' in data
        except:
            return jsonify({'Message': 'Credentials are missing'}), 400
        
        # Validate the credentials
        user = UserModel.query.filter(UserModel.username==data['Username']).first()
        if not user or not user.verify(data['Password']):
            return jsonify({'Message': 'Invalid credentials'}), 401
        
        token = jwt.encode({
            'sub': user.id,
            'iat': int(time.time()),
            'exp': int(time.time()) + 60 * 60 * 24 * 7
        }, secret)

        if 'callback' in data:
            # When a callback url is specified
            response = redirect(data['callback'] + '?jwt=' + token.decode('utf8'))
        else:
            # API interface
            response = make_response(jsonify({'Message': 'Authorized!', 'token': token.decode('utf8')}))
        response.set_cookie('jwt', token.decode('utf8'), httponly=True)

        return response

@app.route('/auth/api/logout', methods=['GET'])
def logout():
    """Creates a jwt blacklist entry"""
    callback = request.args.get('callback')
    # If there's no token then do nothing
    if not request.cookies.get('jwt'):
        if callback: return redirect(callback)
        return jsonify({'Message': 'Unauthorized'}), 401

    token = request.cookies.get('jwt')
    try:
        # If it's not expired
        data = jwt.decode(token, secret)
        entry = jwtBlackList(data['sub'], data['exp'])
        entry.save()
        # Redirect if a callback url is set
        if callback: response = redirect(callback)
        else: return make_response(jsonify({'Message': 'Logged out'})), 401
        response.delete_cookie('jwt')
        return response
    except jwt.ExpiredSignatureError:
        # If the token is expired
        # Redirect if a callback url is set
        if callback: response = redirect(callback)
        else: return make_response(jsonify({'Message': 'Token Expired'})), 401
        response.delete_cookie('jwt')
        return response

@app.route('/auth/api/register', methods=['POST'])
def create_user():
    """Creates a user and stores it in the database"""
    if request.method == 'POST':
        data = request.values

        # Check if no arguments are missing
        try:
            assert 'Username' in data
            assert 'Password' in data
        except:
            return jsonify({'Message': 'Credentials are missing'}), 400
        
        # Validate the credentials
        m = ""
        try:
            assert 4 <= len(data['Username']) <= 120
            m = "username"
            assert len(re.sub(r'[0-9a-zA-Z_\-]', '', data['Username'])) == 0
            m = "uinvalid" + re.sub(r'[0-9a-zA-Z_\-]', '', data['Username'])
            assert UserModel.query.filter(UserModel.username==data['Username']).count() == 0
            m = "exist"
            assert len(data['Password']) >= 8
            m = "pass"
            assert len(re.sub(r'[0-9a-zA-Z_\-]', '', data['Password'])) == 0
            m = "pinvalid"
        except:
            return jsonify({'Message': 'Invalid credentials', 'm': m}), 400

        user = UserModel(data['Username'], data['Password'])
        user.save()

        token = jwt.encode({
            'sub': user.id,
            'iat': int(time.time()),
            'exp': int(time.time()) + 60 * 60 * 24 * 7
        }, secret)
    
        if 'callback' in data:
            # When a callback url is specified
            response = redirect(data['callback'] + '?jwt=' + token.decode('utf8'))
        else:
            # API interface
            response = make_response(jsonify({'Message': 'Authorized!', 'token': token.decode('utf8')}))
        response.set_cookie('jwt', token.decode('utf8'), httponly=True)

        return response

if __name__ == '__main__':
    app.run(debug=True)