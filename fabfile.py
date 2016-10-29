# Just a script to update my personal server.

from fabric.api import *

env.hosts = ['unti@draco.uberspace.de']

@task
def update():
    with cd('~/data/mysteryshack'):
        run('git pull')
        run('make')

    run('svc -du ~/service/mysteryshack')
