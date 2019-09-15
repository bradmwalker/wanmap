from invoke import task


@task
def build_dev(ctx):
    ctx.run('docker build -t bradmwalker/wanmap -f Dockerfile.dev .')
    ctx.run('docker push bradmwalker/wanmap')
