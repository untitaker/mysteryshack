from fabric.api import *

env.hosts = ['unti@draco.uberspace.de']

@task
def update():
    with cd('~/data/mysteryshack'):
        run('git pull')
        with prefix('source rust-setup.sh'):
            run('cargo build --release')

        run('mkdir -p ~/virtual/unterwaditzer.net/bin/')
        run('cp target/release/mysteryshack ~/virtual/unterwaditzer.net/bin/mysteryshack')

    run('svc -du ~/service/mysteryshack')
