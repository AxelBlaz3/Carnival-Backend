from flask import Flask
from routes import api_v1, bcrypt, jwt, mongo, mail
from config import Config
from gevent.pywsgi import WSGIServer


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config())

    app.register_blueprint(api_v1)
    mongo.init_app(app=app)
    mail.init_app(app=app)
    bcrypt.init_app(app=app)
    jwt.init_app(app=app)
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0')
    # http_server = WSGIServer(('0.0.0.0', 5000), app)
    # http_server.serve_forever()
