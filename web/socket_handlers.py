
from flask import Flask
from flask_socketio import SocketIO
socketio = SocketIO(cors_allowed_origins="*")

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'f6f02099cbbdafaf7346e28d70255dfb55c9c8ab5e6a1966'
    socketio.init_app(app)

    @app.route('/')
    def index():
        return '<h1>Dashboard is running...</h1>'

    return app