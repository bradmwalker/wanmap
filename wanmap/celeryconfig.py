from kombu import Exchange, Queue

CELERY_RESULT_BACKEND = 'rpc://'

CELERY_QUEUES = (
    Queue('console', Exchange('default', type='direct'), routing_key='console'),
    Queue('scans', Exchange('scans', type='topic'), routing_key='scans.*'),
)

CELERY_DEFAULT_QUEUE = 'console'
CELERY_DEFAULT_EXCHANGE_TYPE = 'direct'
CELERY_DEFAULT_ROUTING_KEY = 'console'

# TODO: Setup display for Queue registry and route scans
# CELERY_ROUTES = {
#     'wanmap.tasks.exec_nmap_scan': {'queue': 'scans'},
# }
