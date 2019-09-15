from invoke import task
from tenacity import retry, wait_fixed


@task
def build_dev(ctx):
    ctx.run('docker build -t bradmwalker/wanmap -f Dockerfile.dev .')
    ctx.run('docker push bradmwalker/wanmap')


def run_static(c):
    c.run('kubectl apply -f config/init-pv.yaml')
    parts = ('db', 'ram',)
    for part in parts:
        c.run('kubectl apply -f config/dev-{}.yaml'.format(part))


@task
def run_tests(c):
    run_static(c)
    c.run(
        'telepresence -n wanmap-test '
        '--logfile /tmp/wanmap-test-telepresence.log '
        '--docker-run -it --rm -v "$(pwd)":/wanmap '
        'bradmwalker/wanmap inv run-tests-internal',
        pty=True)


@task
def run_tests_internal(c):
    until_postgres_online(c)
    c.run('dropdb -h wanmap-db -U wanmap wanmap_test')
    c.run('createdb -h wanmap-db -U wanmap -O wanmap wanmap_test')
    c.run('py.test -f', pty=True)


@retry(wait=wait_fixed(4))
def until_postgres_online(c):
    c.run('pg_isready -h wanmap-db -U wanmap')
