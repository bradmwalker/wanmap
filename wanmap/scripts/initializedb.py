import os
import sys

from pyramid.paster import get_appsettings, setup_logging
from pyramid.scripts.common import parse_vars
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.schema import CreateTable

from ..schema import get_engine, Persistable


def usage(argv):
    cmd = os.path.basename(argv[0])
    print('usage: %s <config_uri> [var=value]\n'
          '(example: "%s development.ini")' % (cmd, cmd))
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 2:
        usage(argv)
    config_uri = argv[1]
    if config_uri.endswith('test.ini'):
        @compiles(CreateTable, 'postgresql')
        def compile_unlogged(create, compiler, **kwargs):
            if 'UNLOGGED' not in create.element._prefixes:
                create.element._prefixes.append('UNLOGGED')
            return compiler.visit_create_table(create)

    options = parse_vars(argv[2:])
    setup_logging(config_uri)
    settings = get_appsettings(config_uri, name='wanmap', options=options)
    engine = get_engine(settings)
    Persistable.metadata.create_all(engine)
