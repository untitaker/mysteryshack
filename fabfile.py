from fabric.api import *

env.hosts = ['unti@draco.uberspace.de']

@task
def update():
    with cd('~/data/mysteryshack'):
        run('git pull')
        with prefix('source rust-setup.sh'):
            run('cargo build --release')

    run('svc -du ~/service/mysteryshack')
