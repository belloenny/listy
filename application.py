from flask import Flask, make_response, session as login_session, render_template as flask_render, request, redirect, jsonify, url_for, flash, send_from_directory
from sqlalchemy import create_engine, asc, desc
from authentication import fbconnect, fbdisconnect, gconnect, gdisconnect, disconnect
from sqlalchemy.orm import sessionmaker
from models import Base, User, Listing, Category
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from functools import wraps
import requests
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Listings Application"
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

# Connect to Database and create database session
engine = create_engine('sqlite:///listings-app.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

def render_template(template_name, **params):
    params['login_session'] = login_session
    return flask_render(template_name, **params)

def login_required(func):
    @wraps(func) # this requires an import
    def wrapper():
        if 'username' not in login_session:
            return redirect('login')
        else:
            func()
    return wrapper

def cat_exists(func):
    @wraps(func) # this requires an import
    def wrapper(category_name):
        if session.query(Category).filter_by(name=category_name).scalar() is None:
            flash("This category does not exist")
            return redirect(url_for('showListings'))
        else:
            func()
    return wrapper

def listing_exists(func):
    @wraps(func) # this requires an import
    def wrapper(listing_name):
        if session.query(Listing).filter_by(name=listing_name).scalar() is None:
            flash("This listing does not exist")
            return redirect(url_for('showListings'))
        else:
            func(listing_name)
    return wrapper

# Show all listings
@app.route('/')
@app.route('/listy/')
def showListings():
    listings = session.query(Listing).order_by(desc(Listing.date))
    categories = {}
    for cat in session.query(Category).all():
        categories[cat.name] = listings.filter_by(category_id=getCategoryID(cat.name)).count()
    return render_template('listings.html', 
        listings=listings,
        categories=categories)

# show listings filtered by category
@app.route('/listy/<category_name>')
@cat_exists
def showListingsByCat(category_name):
    filteredListings = session.query(Listing).filter_by(category_id=getCategoryID(category_name))
    allListings = session.query(Listing).order_by(asc(Listing.name))
    categories = {}
    for cat in session.query(Category).all():
        categories[cat.name] = allListings.filter_by(category_id=getCategoryID(cat.name)).count()
    return render_template('listings.html', 
        listings=filteredListings, 
        categories=categories, 
        category_name=category_name)

# show listings filtered by username
@app.route('/listy/user/<username>')
def showListingsByUsername(username):
    user = getUserByName(username)
    filteredListings = session.query(Listing).filter_by(user_id=user.id)
    allListings = session.query(Listing).order_by(asc(Listing.name))
    categories = {}
    for cat in session.query(Category).all():
        categories[cat.name] = allListings.filter_by(category_id=getCategoryID(cat.name)).count()
    return render_template('listings.html', 
        listings=filteredListings,
        categories=categories, 
        category_name=username)

# Create a new listing
@login_required
@app.route('/listy/new/', methods=['GET', 'POST'])
def newListing():
    categories = session.query(Category).all()
    if request.method == 'POST':
        if checkIfExists(request.form['name'],Listing):
            existingListing = session.query(Listing).filter_by(name=request.form['name']).one()
            flash('A listing called "%s" already exists. Please re-name your listing.' % existingListing.name)
            return render_template('newListing.html', categories=categories)
        elif request.form['name'] == '':
            flash('Please enter a name for your listing.')
            return render_template('newListing.html', categories=categories)
        elif request.form['new-category'] == '' and request.form['category'] == 'False':
            flash('You must select or create a category')
            return render_template('newListing.html', categories=categories)
        elif request.form['description'] == '':
            flash('You must fill out a description')
            return render_template('newListing.html', categories=categories)
        else:
            imagename = ''
            # check if user uploaded an image
            if request.files['image']:
                if 'image' not in request.files:
                    flash('No file part')
                    return render_template('newListing.html', categories=categories)
                image = request.files['image']
                # if user does not select file, browser also
                # submits an empty part without the filename
                if image.filename == '':
                    flash('No selected image')
                    return redirect(request.url)
                if image and allowed_file(image.filename):
                    imagename = secure_filename(image.filename)
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], imagename))
            if request.form['new-category']:
                if checkIfExists(request.form['new-category'],Category):
                    flash('A category with that name already exists. Please re-name your category.')
                    return render_template('newListing.html', categories=categories)
                else:
                    newCategory = Category(name=request.form['new-category'])
                    session.add(newCategory)
                    session.commit()
                newListing = Listing(
                    name=request.form['name'], 
                    description=request.form['description'], 
                    image=imagename,
                    category_id=getCategoryID(request.form['new-category']),
                    user_id=login_session['user_id'])
                session.add(newListing)
                flash('New Listing "%s" Successfully Created' % newListing.name)
                session.commit()
                return redirect(url_for('showListings'))
            else:
                newListing = Listing(
                    name=request.form['name'], 
                    description=request.form['description'], 
                    image=imagename,
                    category_id=getCategoryID(request.form['category']), 
                    user_id=login_session['user_id'])
                session.add(newListing)
                flash('New Listing "%s" Successfully Created' % newListing.name)
                session.commit()
                return redirect(url_for('showListings'))   
    else:
        return render_template('newListing.html', categories=categories)

# Edit a listing
@login_required
@app.route('/listy/<listing_name>/edit', methods=['GET', 'POST'])
@listing_exists
def editListing(listing_name):
    editedListing = session.query(Listing).filter_by(name=listing_name).one()
    if login_session['user_id'] != editedListing.user_id:
        flash('Your are not authorized to edit this listing')
        return redirect(url_for('showListings'))
    categories = session.query(Category).all()
    if request.method == 'POST':
        if request.form['name']:
            editedListing.name = request.form['name']
        if request.form['description']:
            editedListing.description = request.form['description']
        if request.files['image']:
            if 'image' not in request.files:
                flash('No file part')
                return render_template('newListing.html', categories=categories)
            image = request.files['image']
            # if user does not select file, browser also
            # submits an empty part without the filename
            if image.filename == '':
                flash('No selected image')
                return redirect(request.url)
            if image and allowed_file(image.filename):
                imagename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], imagename))
                editedListing.image = imagename
        if request.form['new-category']:
            if checkIfExists(request.form['new-category'],Category):
                flash('A category with that name already exists. Please re-name your category.')
                return render_template('editListing.html', categories=categories)
            else:
                newCategory = Category(name=request.form['new-category'])
                session.add(newCategory)
                session.commit()
                editedListing.category_id = getCategoryID(request.form['new-category'])
        elif request.form['category']:
            editedListing.category_id = getCategoryID(request.form['category'])
        session.add(editedListing)
        session.commit()
        flash('%s was successfully updated' % editedListing.name)
        return redirect(url_for('showListings'))
    else:
        return render_template('editListing.html', listing=editedListing, categories=categories)

# delete a listing
@login_required
@app.route('/listy/<listing_name>/delete', methods=['GET', 'POST'])
@listing_exists
def deleteListing(listing_name):
    listingToDelete = session.query(
        Listing).filter_by(name=listing_name).one()
    if listingToDelete.user_id != login_session['user_id']:
        flash('Your are not authorized to delete this listing')
        return redirect(url_for('showListings'))
    if request.method == 'POST':
        session.delete(listingToDelete)
        flash('%s Successfully Deleted' % listingToDelete.name)
        session.commit()
        return redirect(url_for('showListings'))
    else:
        return render_template('deleteListing.html', listing=listingToDelete)

# delete a category
@login_required
@app.route('/categories/<category_name>/delete', methods=['GET', 'POST'])
@cat_exists
def deleteCategory(category_name):
    categoryToDelete = session.query(Category).filter_by(name=category_name).one()
    if request.method == 'POST':
        allListings = session.query(Listing).all()
        for listing in allListings:
            if listing.category_id == categoryToDelete.id:
                flash('This category has listings associated with it and cannot be deleted')
                return redirect(url_for('showListings'))
        session.delete(categoryToDelete)
        flash('Category successfully deleted')
        session.commit()
        return redirect(url_for('showListings'))
    else:
        return render_template('deleteCategory.html', category=categoryToDelete)

# delete account
@login_required
@app.route('/delete-account', methods=['GET', 'POST'])
def deleteAccount():
    user = getUserInfo(login_session['user_id'])
    if request.method == 'POST':
        if user.id != login_session['user_id']:
            flash('Your are not authorized to delete this account')
            return redirect(url_for('showListings'))
        userListings = session.query(Listing).filter_by(user_id=login_session['user_id']).all()
        for l in userListings:
            session.delete(l)
            flash('Listing %s has been deleted' % l.name)
            # session.commit()
        session.delete(user)
        flash('Account for %s has been deleted' % user.username)
        session.commit()
        return redirect(url_for('disconnect'))
    else:
        return render_template('deleteAccount.html', user=user)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

# edit profile
@login_required
@app.route('/profile', methods=['GET', 'POST'])
def editProfile():
    user = getUserInfo(login_session['user_id'])
    if user.id != login_session['user_id']:
        flash('Your are not authorized to edit this profile')
        return redirect(url_for('showListings'))
    if request.method == 'POST':
        if request.form['old-password'] and request.form['new-password']:
            if user.verify_password(request.form['old-password']):
                user.hash_password(request.form['new-password'])
                flash("Password updated")
            else:
                flash('Old password is incorrect')
                return render_template('editProfile.html', user=user)
        if request.form['username']:
            if getUserByName(request.form['username']) is None:
                login_session['username'] = request.form['username']
                user.username = request.form['username']
                flash("Username updated")
            else:
                flash("Username already exists.")
                return render_template('editProfile.html', user=user)
        if request.files['picture']:
            # check if the post request has the file part
            if 'picture' not in request.files:
                flash('No file part')
                return render_template('editProfile.html', user=user)
            picture = request.files['picture']
            # if user does not select file, browser also
            # submits an empty part without the filename
            if picture.filename == '':
                flash('No selected image')
                return redirect(request.url)
            if picture and allowed_file(picture.filename):
                picturename = secure_filename(picture.filename)
                picture.save(os.path.join(app.config['UPLOAD_FOLDER'], picturename))
                user.picture = picturename
                login_session['picture'] = user.picture
                flash("Picture updated")
        if request.form['email']:
            if getUserID(request.form['email']) is None:
                login_session['email'] = request.form['email']
                user.email = request.form['email']
                flash("Email address updated")
            else:
                flash("Email address already exists.")
                return render_template('editProfile.html', user=user)
        session.add(user)
        session.commit()
        return render_template('editProfile.html', user=user)
    else:
        return render_template('editProfile.html', user=user)
    
# Show a listing
@app.route('/listy/<listing_name>/')
@listing_exists
def showListing(listing_name):
    listing = session.query(Listing).filter_by(name=listing_name).one()
    return render_template('showListing.html', listing=listing)

# JSON APIs to view Listing Information
@app.route('/listy/<listing_name>/JSON')
@listing_exists
def listingJSON(listing_name):
    listing = session.query(Listing).filter_by(name=listing_name).one()
    return jsonify(listing.serialize)

@app.route('/listy/category/<category_name>/JSON')
@cat_exists
def listingsByCategoryJSON(category_name):
    cat_id = getCategoryID(category_name)
    category = session.query(Category).filter_by(id=cat_id).one()
    listings = session.query(Listing).filter_by(category_id=cat_id).all()
    return jsonify(Category=[category.serializeCat(cat_id,category_name,listings)])

@app.route('/listy/JSON')
def allListingsByCategoryJSON():
    categories = session.query(Category).all()
    catJSON = []
    for c in categories:
        listings = session.query(Listing).filter_by(category_id=c.id).all()
        cat = {
            "Listings" : [r.serialize for r in listings],
            "category_id" : c.id,
            "name" : c.name
        }
        catJSON.append(cat)
    return jsonify(Categories=catJSON)

@app.route('/login')
def showLogin():
    # Create anti-forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print ("access token received %s " % access_token)

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    
    try:
        login_session['provider'] = 'facebook'
        login_session['username'] = data["name"]
        login_session['email'] = data["email"]
        login_session['facebook_id'] = data["id"]
    except:
        print (data)

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output

@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

@app.route('/login-new-user', methods=['GET', 'POST'])
def loginNewUser():
    if request.form['username'] and request.form['password'] and request.form['email']:
        # make sure user doesn't already exist
        if getUserByName(request.form['username']):
            flash("This username already exists, please select another one")
            return redirect(url_for('showLogin'))
        else:
            newUser = User(username=request.form['username'], 
                email=request.form['email'])
            newUser.hash_password(request.form['password'])
            session.add(newUser)
            session.commit()
            login_session['username'] = newUser.username
            login_session['email'] = newUser.email
            login_session['user_id'] = newUser.id
            login_session['provider'] = 'listy'
            return redirect(url_for('showListings'))
    else:
        flash("Please fill out all the forms")
        return redirect(url_for('showLogin'))

@app.route('/login-existing-user', methods=['GET', 'POST'])
def loginExistingUser():
    # make sure form was filled out
    if request.form['existing-username'] and request.form['existing-password']:
        # check if user exists
        if getUserByName(request.form['existing-username']):
            user = session.query(User).filter_by(username=request.form['existing-username']).one()
            # check their password
            if user.verify_password(request.form['existing-password']):
                login_session['username'] = request.form['existing-username']
                login_session['provider'] = 'listy'
                login_session['picture'] = user.picture
                login_session['email'] = user.email
                login_session['user_id'] = user.id

                flash("You are logged in as %s" % login_session['username'])
                return redirect(url_for('showListings'))
            else:
                flash("Your password is incorrect")
                return redirect(url_for('showLogin'))
        else:
            flash("Username does not exist or is incorrect")
            return redirect(url_for('showLogin'))
    else:
        flash("Please fill out all fields")
        return redirect(url_for('showLogin'))

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    print ("access token recieved %s" % access_token)
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;' \
                'border-radius: 150px;-webkit-border-radius: 150px;'\
                '-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'username' in login_session:
        print (login_session['username'])
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            if 'gplus_id' in login_session:
                del login_session['gplus_id']
            if 'credentials' in login_session:
                del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        if 'username' in login_session:
            del login_session['username']
        if 'email' in login_session:
            del login_session['email']
        if 'picture' in login_session:
            del login_session['picture']
        if 'user_id' in login_session:
            del login_session['user_id']
        if 'provider' in login_session:
            del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showListings'))
    else:
        if 'username' in login_session:
            del login_session['username']
        if 'email' in login_session:
            del login_session['email']
        if 'picture' in login_session:
            del login_session['picture']
        if 'user_id' in login_session:
            del login_session['user_id']
        if 'provider' in login_session:
            del login_session['provider']
        flash("You were not logged in")
        return redirect(url_for('showListings'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# User Helper Functions

def checkIfExists(name,model_type):
    if session.query(model_type).filter_by(name=name).count():
        return True
    else:
        return False

def createUser(login_session):
    newUser = User(username=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserByName(username):
    try:
        user = session.query(User).filter_by(username=username).one()
        return user
    except:
        return None

def getUserInfo(user_id):
    try:
        user = session.query(User).filter_by(id=user_id).one()
        return user
    except:
        return None

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

def getCategoryID(name):
    try:
        category = session.query(Category).filter_by(name=name).one()
        return category.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)  