from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String, default='https://example.com/default-profile.png')
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', back_populates='user', cascade="all, delete-orphan")

    @property
    def password(self):
        raise Exception("Password is not accessible")

    @password.setter
    def password(self, value):
        self._password_hash = bcrypt.generate_password_hash(value).decode("utf-8")

    @property
    def password_hash(self):
        raise AttributeError("Password hash is not a readable attribute")
    
    @password_hash.setter
    def password_hash(self, value):
        self._password_hash = bcrypt.generate_password_hash(value).decode("utf-8")

    # Returns True if a given password matches the instance's `password_hash`.
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)
    
    @validates('username')
    def validate_username(self, key, value):
        if not value:
            raise ValueError("Username is required")
        return value
    
        # Add this to set a default password if none is provided
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Check if password hash is missing and set a default one
        if not self._password_hash:
            self.password = "default_password"  # Set a default password

class Recipe(db.Model):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # user_id is nullable

    user = db.relationship('User', back_populates='recipes')

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.user_id:
            # Get the first user in the database
            default_user = db.session.query(User).first()
            if default_user:
                # Assign the user_id directly
                self.user_id = default_user.id
            else:
                # Handle the case where no users exist
                # You might want to raise an exception or handle it as per your application's logic
                raise ValueError("No users available to assign as default.")


