from flask import Flask


def setup_test_app(blueprint):
    app = Flask('test_app')
    app.config['TESTING'] = True
    app.register_blueprint(blueprint)
    return app
