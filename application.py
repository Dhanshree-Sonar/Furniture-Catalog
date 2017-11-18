from flask import Flask, render_template, request, url_for
from flask import redirect, jsonify, flash
# Imports for sql operations
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
# Imports to generate tokens to prevent forgery
from flask import session as login_session
import random
import string
# Imports to callback method for google login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Furniture Catalog Application"

engine = create_engine('sqlite:///furniturecatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Authenticating a user using Google
@app.route('/gconnect', methods=['POST'])
def gconnect():
    print "Enter Gconn"
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
    url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
        access_token)
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
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check to see if user is already logged in
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
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

    # Store required data into login_session
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if user exists, if it doesn't make a new enter.
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# Disconnecting a logged in google user
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
        return redirect(url_for('showCategories'))
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Create a new user
def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Retrieve user data based on user_id
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Retrieve user id based on user email id
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# JSON endpoints

# JSON endpoint for all category names
@app.route('/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[category.serialize for category in categories])


# JSON endpoint for items in particular category
@app.route('/category/<int:cat_id>/items/JSON')
def categoryItemsJSON(cat_id):
    items = session.query(Item).filter_by(cat_id=cat_id).all()
    return jsonify(Items=[item.serialize for item in items])


# JSON endpoint for all items in database
@app.route('/items/JSON')
def itemsJSON():
    items = session.query(Item).all()
    return jsonify(Items=[item.serialize for item in items])


# JSON endpoint for item details
@app.route('/item/<int:item_id>/JSON')
def restaurantMenuJSON(item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


# Show login page and create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


def recentlyAddedItems():
    items = session.query(Item.id, Item.name, Item.cat_id, Category.name
                          ).join(Category, Category.id == Item.cat_id
                                 ).order_by(Item.id.desc()).limit(10)
    return items


# Show all categories
@app.route('/')
@app.route('/categories')
def showCategories():
    categories = session.query(Category).all()
    recent_items = recentlyAddedItems()
    if 'username' not in login_session:
        return render_template('publicCategories.html', categories=categories,
                               session=login_session,
                               recent_items=recent_items)
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('categories.html', categories=categories,
                               session=login_session,
                               recent_items=recent_items, user=user)


# Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return '''<script> function myFunction(){
               alert('You need to login to create new category.');
               location.replace("/login");}</script>
               <body onload='myFunction()'></body>'''
    categories = session.query(Category).all()
    user = getUserInfo(login_session['user_id'])
    if request.method == 'POST':
        new_category = Category(name=request.form['cat_name'],
                                user_id=login_session['user_id'])
        session.add(new_category)
        session.commit()
        message = "New Category '" + request.form['cat_name'] + "' added!!"
        flash(message)
        return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html', session=login_session,
                               categories=categories, user=user)


# Edit a category
@app.route('/category/<int:cat_id>/edit/', methods=['GET', 'POST'])
def editCategory(cat_id):
    if 'username' not in login_session:
        return '''<script> function myFunction(){
               alert('You need to login to edit a category.');
               location.replace("/login");}</script>
               <body onload='myFunction()'></body>'''

    edit_category = session.query(Category).filter_by(id=cat_id).one()
    old_category_name = edit_category.name
    categories = session.query(Category).all()
    user = getUserInfo(login_session['user_id'])
    if request.method == 'POST':
        edit_category.name = request.form['cat_name']
        session.add(edit_category)
        session.commit()
        message = "Category '" + old_category_name + "' updated to '"
        message += request.form['cat_name'] + "'!!"
        flash(message)
        return redirect(url_for('showCategories'))
    else:
        return render_template('editCategory.html', category=edit_category,
                               session=login_session, categories=categories,
                               user=user)


# Delete a category
@app.route('/category/<int:cat_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(cat_id):
    if 'username' not in login_session:
        return '''<script> function myFunction(){
               alert('You need to login to delete a category.');
               location.replace("/login");}</script>
               <body onload='myFunction()'></body>'''

    delete_category = session.query(Category).filter_by(id=cat_id).one()
    old_category_name = delete_category.name
    categories = session.query(Category).all()
    user = getUserInfo(login_session['user_id'])
    if request.method == 'POST':
        session.delete(delete_category)
        session.commit()
        # Delete items which are under cat_id
        session.query(Item).filter_by(cat_id=cat_id).delete()
        session.commit()
        message = "Category '" + old_category_name + "' deleted!!"
        flash(message)
        return redirect(url_for('showCategories'))
    else:
        return render_template('deleteCategory.html', category=delete_category,
                               session=login_session, categories=categories,
                               user=user)


# Show all item for particular Category
@app.route('/category/<int:cat_id>/')
@app.route('/category/<int:cat_id>/items/')
def showItems(cat_id):
    category = session.query(Category).filter_by(id=cat_id).one()
    items = session.query(Item).filter_by(cat_id=cat_id).all()
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template('publicItems.html', category=category,
                               session=login_session, categories=categories,
                               items=items)
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('items.html', category=category, items=items,
                               session=login_session, categories=categories,
                               user=user)


# Create a new item
@app.route('/category/<int:cat_id>/item/new/', methods=['GET', 'POST'])
def newItem(cat_id):
    if 'username' not in login_session:
        return '''<script> function myFunction(){
               alert('You need to login to craete a new Item.');
               location.replace("/login");}</script>
               <body onload='myFunction()'></body>'''
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=cat_id).one()
    if request.method == 'POST':
        new_item = Item(name=request.form['new_name'], cat_id=cat_id,
                        description=request.form['new_description'],
                        user_id=login_session['user_id'])
        session.add(new_item)
        session.commit()
        message = "New Item '" + request.form['new_name']
        message += "' added to the '" + category.name + "'!!"
        flash(message)
        return redirect(url_for('showItems', cat_id=cat_id))
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('newItem.html', cat_id=cat_id, user=user,
                               session=login_session, categories=categories,
                               category=category)


# Show item Description
@app.route('/category/<int:cat_id>/item/<int:item_id>/description/',
           methods=['GET', 'POST'])
def itemDescription(cat_id, item_id):
    category = session.query(Category).filter_by(id=cat_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    creator = getUserInfo(item.user_id)
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template('publicItemDescription.html', item=item,
                               category=category, categories=categories)
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('itemDescription.html', category=category,
                               item=item, session=login_session,
                               categories=categories, user=user)


# Edit particular items
@app.route('/category/<int:cat_id>/item/<int:item_id>/edit/',
           methods=['GET', 'POST'])
def editItem(cat_id, item_id):
    categories = session.query(Category).all()
    item = session.query(Item).filter_by(id=item_id).one()
    old_item_name = item.name
    # Check if user has logged in
    if 'username' not in login_session:
        return '''<script> function myFunction(){
               alert('You need to login to Edit a Item.');
               location.replace("/login");}</script>
               <body onload='myFunction()'></body>'''
    # Check if user has authority to edit the item
    if item.user_id != login_session['user_id']:
        return '''<script> function myFunction(){
               alert('You are not authorized to Edit this item.');
               location.replace("/");}</script>
               <body onload='myFunction()'></body>'''
    category = session.query(Category).filter_by(id=cat_id).one()
    if request.method == 'POST':
        new_cat_name = request.form['new_category']
        new_category = session.query(Category).filter_by(
            name=new_cat_name).one()
        item.user_id = login_session['user_id']
        item.name = request.form['new_name']
        item.description = request.form['new_description']
        item.cat_id = new_category.id

        session.add(item)
        session.commit()
        message = "Item '" + old_item_name + "' of '" + category.name
        message += "' has been updated!!"
        flash(message)
        return redirect(url_for('showItems', cat_id=cat_id))
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('editItem.html', categories=categories,
                               item=item, cat_id=cat_id, category=category,
                               session=login_session, user=user)


# Delete particular items
@app.route('/category/<int:cat_id>/item/<int:item_id>/delete/',
           methods=['GET', 'POST'])
def deleteItem(cat_id, item_id):
    category = session.query(Category).filter_by(id=cat_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    old_item_name = item.name
    # Check if user has logged in
    if 'username' not in login_session:
        return '''<script> function myFunction(){
               alert('You need to login to Delete a Item.');
               location.replace("/login");}</script>
               <body onload='myFunction()'></body>'''
    # Check if user has authority to delete the item
    if item.user_id != login_session['user_id']:
        return '''<script> function myFunction(){
               alert('You are not authorized to Delete this item.');
               location.replace("/");}</script>
               <body onload='myFunction()'></body>'''
    categories = session.query(Category).all()
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        message = "Item '" + old_item_name + "' of '" + category.name
        message += "' has been deleted!!"
        flash(message)
        return redirect(url_for('showItems', cat_id=cat_id))
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('deleteItem.html', category=category, item=item,
                               session=login_session, categories=categories,
                               user=user)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
