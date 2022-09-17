from flask import Blueprint, request, jsonify, render_template, Response
from helpers import token_required
from models import CarSchema, db, User, Car, car_schema, cars_schema

api = Blueprint('api',__name__,url_prefix='/api')

@api.route('/cars', methods=['OPTIONS'])
@token_required
def preflight(current_user_token):
    response = Response()
    response.headers.add('Access-Control-Allow-Origin','*')
    response.headers.add('Access-Control-Allow-Headers','Content-Type, x-access-token')
    response.headers.add('Access-Control-Allow-Methods','POST, GET, OPTIONS, DELETE')


# Create
@api.route('/cars',methods=['POST'])
@token_required
def create_car(current_user_token):
    vin = request.json['vin']
    make  =request.json['make']
    model = request.json['model']
    year = request.json['year']
    color = request.json['color']
    user_token = current_user_token.token

    print(f'BIG TESTER: {current_user_token.token}')

    car = Car(vin, make, model,year,color, user_token=user_token)

    db.session.add(car)
    db.session.commit()

    response = car_schema.dump(car)
    return jsonify(response)

#Read
@api.route('/cars',methods=['GET'])
@token_required
def get_car(current_user_token):
    collector = current_user_token.token
    cars = Car.query.filter_by(user_token = collector).all()
    response = cars_schema.dump(cars)
    return jsonify(response)

@api.route('/cars/<id>',methods=['GET'])
@token_required
def get_single_car(current_user_token,id):
    car = Car.query.get(id)
    response = car_schema.dump(car)
    return jsonify(response)

#Update
@api.route('/cars/<id>',methods=["POST", "PUT"])
@token_required
def update_car(current_user_token, id):
    car = Car.query.get(id)
    car.make = request.json['make']
    car.model = request.json['model']
    car.year = request.json['year']
    car.color = request.json['color']
    car.user_token = current_user_token.token

    db.session.commit()
    response = car_schema.dump(car)
    return jsonify(response)

#Delete
@api.route('/cars/<id>',methods=["DELETE"])
@token_required
def delete_car(current_user_token, id):
    car = Car.query.get(id)
    db.session.delete(car)
    db.session.commit()

    response = car_schema.dump(car)
    return jsonify(response)