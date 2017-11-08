from flask import (Flask, render_template, request,
                   redirect, jsonify, url_for, flash)
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)


# Connect to Database and create database session
engine = create_engine('postgresql://catalog:catalog@localhost:5432/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# -----------------------------------------------------
# Google connect code.

CLIENT_ID = json.loads(
    open('/var/www/catalog/client_secrets.json', 'r')
    .read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# Google connect function.
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(
            json.dumps(
                'Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(
            'client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps(
                'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
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
            json.dumps(
                "Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps(
                "Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'),
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
    output += (' " style = "width: 300px; height: 300px;border-radius:'
               '150px;-webkit-border-radius: 150px;'
               '-moz-border-radius: 150px;"> ')
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# Google disconnect.
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    print access_token
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result.status == 200:
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        flash('Successfully logged out.')
        return redirect(url_for('showCatalog'))
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# ------------------------------------------------------
# Functions to provide JSON outputs.
@app.route('/JSON/')
@app.route('/catalog/JSON/')
def showCatalogJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in categories])


@app.route('/category/<int:category_id>/JSON/')
def showCategoryJSON(category_id):
    category = getCategoryByID(category_id)
    items = getItems(category_id)
    return jsonify(Category=[category.serialize],
                   Items=[i.serialize for i in items])


@app.route('/category/<int:category_id>/<int:item_id>/JSON/')
def showItemJSON(category_id, item_id):
    item = getItem(item_id)
    return jsonify(Item=[item.serialize])

# ------------------------------------------------------


# Catalog main page.
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    categories = session.query(Category).all()
    loggedin = checkLoginStatus()
    if loggedin:
        return render_template('catalog.html',
                               categories=categories,
                               loggedin=loggedin)
    else:
        return render_template('catalogpublic.html',
                               categories=categories,
                               loggedin=loggedin)


# ---------------------------------------------------

# Category main page.
@app.route('/category/<int:category_id>/')
def showCategory(category_id):
    category = getCategoryByID(category_id)
    items = getItems(category_id)
    loggedin = checkLoginStatus()

    if loggedin:
        user = getUserInfo(login_session['user_id'])
        return render_template('category.html',
                               category=category,
                               items=items,
                               loggedin=loggedin,
                               user=user)
    else:
        return render_template('categorypublic.html',
                               category=category,
                               items=items,
                               loggedin=loggedin)


# Category create page.
@app.route('/category/new',
           methods=['GET', 'POST'])
def newCategory():

    if 'username' not in login_session:
        response = make_response(json.dumps(
            'You have to be logged in to access this page.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    elif request.method == 'POST':
        createCategory(request.form['category'])
        flash("You have added a new Category.")
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newcategory.html')


# Category edit page.
@app.route('/category/<int:category_id>/edit',
           methods=['GET', 'POST'])
def editCategory(category_id):
    category = getCategoryByID(category_id)
    if 'username' not in login_session:
        response = make_response(json.dumps(
            'You have to be logged in to access this page.'),
                                 400)
        response.headers['Content-Type'] = 'application/json'
        return response
    elif category.user_id != login_session['user_id']:
        response = make_response(json.dumps(
            'You are not authorized to edit categories you have not created.'),
                                 400)
        response.headers['Content-Type'] = 'application/json'
        return response
    elif request.method == 'POST':
        editCategory(category, request.form['category'])
        flash('Category successfully edited.')
        return redirect(url_for('showCategory',
                                category_id=category_id))
    else:
        return render_template('editcategory.html',
                               category=category)


# Category delete page.
@app.route('/category/<int:category_id>/delete',
           methods=['GET', 'POST'])
def deleteCategory(category_id):
    category = getCategoryByID(category_id)
    if 'username' not in login_session:
        response = make_response(json.dumps(
            'You have to be logged in to access this page.'),
                                 400)
        response.headers['Content-Type'] = 'application/json'
        return response
    elif category.user_id != login_session['user_id']:
        response = make_response(json.dumps(
            'You are not authorized to delete other users categories.'),
                                 400)
        response.headers['Content-Type'] = 'application/json'
        return response
    elif request.method == 'POST':
        deleteCategory(category)
        flash("Category successfully deleted.")
        return redirect(url_for('showCatalog'))
    else:    
        return render_template('deletecategory.html',
                               category=category)

# -----------------------------------------------------


# Item main page
@app.route('/category/<int:category_id>/<int:item_id>')
def showItem(category_id, item_id):
    category = getCategoryByID(category_id)
    item = getItem(item_id)
    loggedin = checkLoginStatus()

    if loggedin:
        user = getUserInfo(login_session['user_id'])
        return render_template('item.html',
                               category=category,
                               item=item,
                               loggedin=loggedin,
                               user=user)
    else:
        return render_template('itempublic.html',
                               category=category,
                               item=item,
                               loggedin=loggedin)


# Item create page
@app.route('/category/<int:category_id>/new/',
           methods=['GET', 'POST'])
def newItem(category_id):
    
    category = getCategoryByID(category_id)
    if 'username' not in login_session:
        response = make_response(json.dumps(
            'You have to be logged in to access this page.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    elif request.method == 'POST':
        createItem(request.form['name'],
                   request.form['description'], category_id)
        flash("You have added a new Item.")
        return redirect(url_for('showCategory', category_id=category_id))
    else: 
        return render_template('newitem.html', category=category)


# Item edit page
@app.route('/category/<int:category_id>/<int:item_id>/edit/',
           methods=['GET', 'POST'])
def editItem(category_id, item_id):
    
    category = getCategoryByID(category_id)
    item = getItem(item_id)
    if 'username' not in login_session:
        response = make_response(json.dumps(
            'You have to be logged in to access this page.'),
                                 400)
        response.headers['Content-Type'] = 'application/json'
        return response
    elif item.user_id != login_session['user_id']:
        response = make_response(json.dumps(
            'You are not authorized to edit items you have not created.'),
                                 400)
        response.headers['Content-Type'] = 'application/json'
        return response
    elif request.method == 'POST':
        editItem(item, request.form['name'], request.form['description'])
        flash("Item successfully edited.")
        return redirect(url_for('showCategory', category_id=category_id))
    else:   
        return render_template('edititem.html', category=category, item=item)


# Item delete page
@app.route('/category/<int:category_id>/<int:item_id>/delete/',
           methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    item = getItem(item_id)
    if 'username' not in login_session:
        response = make_response(json.dumps(
            'You have to be logged in to access this page.'),
                                 400)
        response.headers['Content-Type'] = 'application/json'
        return response
    elif item.user_id != login_session['user_id']:
        response = make_response(json.dumps(
            'You are not authorized to delete items you have not created.'),
                                 400)
        response.headers['Content-Type'] = 'application/json'
        return response
    elif request.method == 'POST':
        deleteItem(item)
        flash("Item successfully deleted.") 
        return redirect(url_for('showCategory',
                                category_id=category_id))
    else:  
        return render_template('deleteitem.html',
                               category_id=category_id,
                               item=item)

# -----------------------------------------------------------


# Function to check if a user is logged in.
def checkLoginStatus():
    if 'username' in login_session:
        return True
    else:
        return False                   

# -----------------------------------------------------------

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session[
                   'email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Category Helper Functions
def createCategory(name):
    newcategory = Category(name=name,
                           user_id=login_session['user_id'])
    session.add(newcategory)
    session.commit()


def getCategoryByID(category_id):
    category = session.query(Category).filter_by(
        id=category_id).one()
    return category


def deleteCategory(category):
    session.delete(category)
    session.commit()


def editCategory(category, name):
    category.name = name
    session.add(category)
    session.commit()
    

# Item Helper Functions

def createItem(name, description, category_id):
    newItem = Item(name=name, description=description,
                   category_id=category_id,
                   user_id=login_session['user_id'])
    session.add(newItem)
    session.commit()


def getItems(category_id):
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return items


def getItem(item_id):
    item = session.query(Item).filter_by(
        id=item_id).one()
    return item


def editItem(item, name, description):
    item.name = name
    item.description = description
    session.add(item)
    session.commit()


def deleteItem(item):
    session.delete(item)
    session.commit()
    
    
# -----------------------------------------------------------
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
