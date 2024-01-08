#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

# @app.before_request
# def check_if_logged_in():
#     if not session['user_id'] and request.endpoint == 'recipes' and request.endpoint == 'logout':
#         return make_response({'errors': ['unauthorized']}, 401)

class Signup(Resource):
    def post(self):
        try:
            form_data = request.get_json()
            user = User(username=form_data.get('username'),
                        image_url=form_data.get('image_url'),
                        bio=form_data.get('bio'))
            # if form_data['password'] == form_data['password_confirmation']:
            #     user.password_hash = form_data['password']
            # else:
            #     return make_response({"message" : "Password does not match"}, 422)
            user.password_hash = form_data['password']
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return make_response(user.to_dict(), 201)
        
        except IntegrityError as error:
            error_message = error.args
            return make_response({"errors": error_message}, 422)
    

    
class CheckSession(Resource):
    def get(self):
        user = User.query.filter(User.id == session.get('user_id')).first()
        if user:
            return make_response(user.to_dict(), 200)
        else:
            return make_response({'message': 'Not Authorized'}, 401)

class Login(Resource):
    def post(self):
        form_data = request.get_json()
        username = form_data['username']
        password = form_data['password']

        user = User.query.filter(User.username == username).first()
        if user:
            if user.authenticate(password):
                session["user_id"] = user.id
                return make_response(user.to_dict(), 200)
            else:
               return make_response({"errors":["Username and/or password not valid"]}, 401)
        else:
            return make_response({"errors":["Username and/or password not valid"]}, 401)


class Logout(Resource):
    def delete(self):
        if session['user_id']:
            session['user_id'] = None
            return make_response({}, 204)
        else:
            return make_response({'errors': ['unauthorized']}, 401)

        
class RecipeIndex(Resource):
    def get(self):
        if session['user_id']:
            user = User.query.filter(User.id == session["user_id"]).first()
            recipes = [recipe.to_dict() for recipe in user.recipes]
            return make_response(recipes, 200)
        else:
            return make_response({'errors': ['unauthorized']}, 401)

        
    def post(self):
        try:
            form_data = request.get_json()
            new_recipe = Recipe(
                title =form_data['title'],
                instructions=form_data['instructions'],
                minutes_to_complete=form_data['minutes_to_complete']
            )
            new_recipe.user_id = session["user_id"]
            db.session.add(new_recipe)
            db.session.commit()
            return make_response(new_recipe.to_dict(), 201)
        except:
            return make_response({'errors':['Invalid recipe']}, 422)

        

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)