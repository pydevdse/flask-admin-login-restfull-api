from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask import Flask,  jsonify, redirect,  request, url_for
from flask_admin import helpers as admin_helpers
import os
from flask_security import auth_required
from flask_sqlalchemy import SQLAlchemy
from flask_security.models import fsqla_v2 as fsqla
from flask_security import current_user, Security, SQLAlchemyUserDatastore
from flask_restful import Resource, Api

app = Flask(__name__)
api = Api(app)

app.config['SECURITY_PASSWORD_SALT'] = 'none'
# Configure application to route to the Flask-Admin index view upon login
app.config['SECURITY_POST_LOGIN_VIEW'] = '/admin/'
# Configure application to route to the Flask-Admin index view upon logout
app.config['SECURITY_POST_LOGOUT_VIEW'] = '/admin/'
# Configure application to route to the Flask-Admin index view upon registering
app.config['SECURITY_POST_REGISTER_VIEW'] = '/admin/'
# Configure application to not send an email upon registration
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['FLASK_ADMIN_SWATCH'] = 'darkly'
app.config['DEBUG'] = True
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['SECRET_KEY'] = "super secret key"
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get("SECURITY_PASSWORD_SALT", '146585145368132386173505678016728509634')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECURITY_REGISTERABLE'] = True
#app.config['SECURITY_LOGIN_URL'] = '/login_user'

db = SQLAlchemy(app)

fsqla.FsModels.set_db_info(db)

class Role(db.Model, fsqla.FsRoleMixin):
    def __str__(self):
        return self.name

class User(db.Model, fsqla.FsUserMixin):
    def __str__(self):
        return self.email

class UserModelView(ModelView):
    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated)

    def _handle_view(self, email):
        if not self.is_accessible():
            return redirect(url_for('security.login'))

    column_list = ['email', 'password', 'role']

admin = Admin(app, name='Test', template_mode='bootstrap3')
admin.add_view(UserModelView(User, db.session))
admin.add_view(UserModelView(Role, db.session))

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@app.before_first_request
def create_user():
    if db.session.query(User).filter_by(email='admin').count()==0:
        db.drop_all()
        db.create_all()
        user_datastore.create_user(email='admin', password='admin')
        db.session.commit()


@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template = admin.base_template,
        admin_view = admin.index_view,
        get_url = url_for,
        h = admin_helpers
    )

# Views

@app.route("/")
@auth_required()
def home():
    return redirect( url_for('admin.index') )

@app.route('/login_user')
def login():
    return '<h3>Login</h3>'

class ApiLogin(Resource):
    def get(self):
        print('get')
        return
    def post(self):
        if not request.json or not 'username' in request.json or not 'password' in request.json:
            return jsonify({"eroor": "json type error"})
        user = db.session.query(User).filter_by(email=request.json['username']).first()
        #for att in dir(user):
        #    print(att, getattr(user, att))
        if user and user.verify_and_update_password(request.json['password']):
            if user.roles == []: role = 'not roles'
            else: 
                role = [r.name for r in user.roles]
            print(role)
            user_info = {'username': user.email, 'user_id': user.id, 'role': str(role)}
            return jsonify(user_info)
        return jsonify({'error': 'user not found or password incorrect'})

api.add_resource(ApiLogin, '/api_login')

if __name__ == '__main__':
    app.run()
