import subprocess
import sys

from flask_script import Manager

from flack import create_app, db

manager = Manager(create_app)

@manager.command
def createdb(drop_first=False):
    #creates the database
    if drop_first:
        db.drop_all()
    db.create_all()

@manager.command
def test():
    #run unit tests
    tests = subprocess.call(['python', '-c', 'import tests; tests.run()'])
    sys.exit(tests)

@manager.command
def lint():
    #runs code linter
    lint = subprocess.call(['flake8', '--ignore=E402', 'flack/', 'manage.py', 'tests/']) == 0

    if lint:
        print('OK')
    sys.exit(lint)

if __name__ == '__main__':
    manager.run()
