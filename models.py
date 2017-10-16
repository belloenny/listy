# -*- coding: utf-8 -*-
from flask import jsonify
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
import psycopg2
from passlib.apps import custom_app_context as pwd_context
import random, string, datetime
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()

secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in = expiration)
        return s.dumps({'id': self.id })

    def return_username(self):
        return self.username

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            #Valid Token, but expired
            return None
        except BadSignature:
            #Invalid Token
            return None
        user_id = data['id']
        return user_id

class Category(Base):
  __tablename__ = 'category'
  id = Column(Integer, primary_key = True)
  name = Column(String, unique=True, index=True)

  @staticmethod
  def serializeCat(cat_id,cat_name,listings):
    return {
      'category': cat_name,
      'cat_id': cat_id,
      'listings': [r.serialize for r in listings]
    }

  @staticmethod
  def serialize(listings):
    return {
      'listings': [r.serialize for r in listings]
    }

  def return_category_name(self):
      return self.name

class Listing(Base):
  __tablename__ = 'listing'
  id = Column(Integer, primary_key = True)
  name = Column(String, unique=True, index=True)
  description = Column(String)
  image = Column(String)
  category_id = Column(Integer, ForeignKey('category.id'))
  category = relationship(Category)
  user_id = Column(Integer, ForeignKey('users.id'))
  user = relationship(User)
  date = Column(DateTime, default=datetime.datetime.utcnow)
  
  #Add a property decorator to serialize information from this database
  @property
  def serialize(self):
    return {
      'id' : self.id,
      'name': self.name,
      'description': self.description,
      'image' : self.image,
      'category' : self.category.return_category_name(),
      'user_id' : self.user_id,
      'listing_author' : self.user.return_username(),
      'published' : self.date.strftime("%m/%d/%Y at %I:%M %p")
    }

engine = create_engine('postgresql://catalog:password@localhost/listings')
 

Base.metadata.create_all(engine)