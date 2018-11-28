from webapp import app, wappdb
from webapp.models import User


@app.shell_context_processor
def make_shell_context():
    return {'db': wappdb, 'User': User}
