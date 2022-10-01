from functools import wraps
import secrets
from flask import request, jsonify, json
import decimal

from models import User

def token_required(our_flask_function):
    @wraps(our_flask_function)
    def decorated(*args, **kwargs):
        token = None

        res = 'Headers: '
        for key in request.headers:
            res = res + str(request.headers[key])+" / "
        return jsonify({'request':res})

        if 'Content-Type' in request.headers:
            return jsonify({'a':str(request.headers['Content-Type'])})

        if not 'xaccesstoken' in request.headers:
            return jsonify({'message':'Header is missing'}), 401
        else:
            token = request.headers['xaccesstoken'].split(' ')[1]

        if not token:
            return jsonify({'message':'invalid token header: '+request.headers['xaccesstoken']}), 401

        try:
            current_user_token = User.query.filter_by(token=token).first()
            print(token)
            print(current_user_token)
        except:
            owner = User.query.filter_by(token=token).first()

            if token != owner.token and secrets.compare_digest(token, owner.token):
                return jsonify({'message':'Token is invalid.'})
        return our_flask_function(current_user_token, *args, **kwargs)            
    return decorated

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            return str(obj)
        return super(JSONEncoder, self).default(obj)
