# Run a test server.
from app import app, setup_app

setup_app(app)
app.run(host='0.0.0.0', port=5000, debug=True)