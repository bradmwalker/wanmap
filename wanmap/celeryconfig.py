from kombu import Exchange, Queue

CELERY_RESULT_BACKEND = 'rpc://'

CELERY_QUEUES = (
    Queue('console', Exchange('default', type='direct'), routing_key='console'),
)

CELERY_CREATE_MISSING_QUEUES = False
CELERY_WORKER_DIRECT = True
CELERY_DEFAULT_QUEUE = 'console'
CELERY_DEFAULT_ROUTING_KEY = 'console'


class ScanRouter:

    def route_for_task(self, task, args=None, kwargs=None):
        if task == 'wanmap.tasks.exec_nmap_scan':
            scanner_name = args[0]
            return {
                'exchange': 'C.dq',
                'routing_key': 'scanner@{}'.format(scanner_name)
            }
        return None

CELERY_ROUTES = (ScanRouter(),)
