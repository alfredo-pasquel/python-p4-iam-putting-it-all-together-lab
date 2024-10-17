#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
import sys

from config import app, db, api
from models import User, Recipe

if 'pytest' in sys.modules:
    with app.app_context():
        db.drop_all()
        db.create_all()


class Signup(Resource):
    def post(self):
        data = request.get_json()

        try:
            username = data.get('username')
            password = data.get('password')
            image_url = data.get('image_url', '')
            bio = data.get('bio', '')

            if not username or not password:
                return {'error': 'Username and password are required'}, 422

            new_user = User(username=username, image_url=image_url, bio=bio)
            new_user.password = password  # Correct way to set password

            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id

            response_data = {
                'id': new_user.id,
                'username': new_user.username,
                'image_url': new_user.image_url,
                'bio': new_user.bio
            }
            return response_data, 201

        except IntegrityError:
            db.session.rollback()
            return {'error': 'Username already exists'}, 422
        except Exception as e:
            db.session.rollback()
            return {'error': 'An error occurred', 'details': str(e)}, 500


class CheckSession(Resource):
    def get(self):
        try:
            user_id = session.get('user_id')

            if not user_id:
                return {'error': 'Unauthorized'}, 401

            user = db.session.get(User, user_id)

            if not user:
                return {'error': 'User not found'}, 404

            response_data = {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }
            return response_data, 200

        except Exception as e:
            db.session.rollback()
            return {'error': 'An error occurred', 'details': str(e)}, 500

class Login(Resource):
    def post(self):
        data = request.get_json()

        try:
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return {'error': 'Username and password are required'}, 400

            user = User.query.filter_by(username=username).first()

            if user and user.authenticate(password):
                session['user_id'] = user.id

                response_data = {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }
                return response_data, 200
            else:
                return {'error': 'Invalid username or password'}, 401

        except Exception as e:
            db.session.rollback()
            return {'error': 'An error occurred', 'details': str(e)}, 500

class Logout(Resource):
    def delete(self):
        try:
            if 'user_id' in session and session['user_id']:
                session.pop('user_id', None)
                return '', 204
            else:
                return {'error': 'Unauthorized'}, 401

        except Exception as e:
            db.session.rollback()
            return {'error': 'An error occurred', 'details': str(e)}, 500

class RecipeIndex(Resource):
    def get(self):
        try:
            user_id = session.get('user_id')
            if not user_id:
                return {'error': 'Unauthorized'}, 401

            recipes = Recipe.query.all()
            recipe_list = []
            for recipe in recipes:
                recipe_data = {
                    'id': recipe.id,
                    'title': recipe.title,
                    'instructions': recipe.instructions,
                    'minutes_to_complete': recipe.minutes_to_complete,
                    'user': {
                        'id': recipe.user.id,
                        'username': recipe.user.username,
                        'image_url': recipe.user.image_url,
                        'bio': recipe.user.bio
                    }
                }
                recipe_list.append(recipe_data)

            return recipe_list, 200

        except Exception as e:
            db.session.rollback()
            return {'error': 'An error occurred', 'details': str(e)}, 500

    def post(self):
        try:
            user_id = session.get('user_id')
            if not user_id:
                return {'error': 'Unauthorized'}, 401

            data = request.get_json()
            title = data.get('title')
            instructions = data.get('instructions')
            minutes_to_complete = data.get('minutes_to_complete')

            # Basic validation
            errors = {}
            if not title:
                errors['title'] = 'Title is required.'
            if not instructions or len(instructions) < 50:
                errors['instructions'] = 'Instructions must be at least 50 characters long.'
            if not minutes_to_complete:
                errors['minutes_to_complete'] = 'Minutes to complete is required.'

            if errors:
                return {'errors': errors}, 422

            # Get the user instance
            user = db.session.get(User, user_id)
            if not user:
                return {'error': 'User not found'}, 404

            # Create new recipe
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user.id  # Associate the recipe with the logged-in user
            )

            db.session.add(new_recipe)
            db.session.commit()

            recipe_data = {
                'id': new_recipe.id,
                'title': new_recipe.title,
                'instructions': new_recipe.instructions,
                'minutes_to_complete': new_recipe.minutes_to_complete,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }
            }

            return recipe_data, 201

        except Exception as e:
            db.session.rollback()
            return {'error': 'An error occurred', 'details': str(e)}, 500


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
