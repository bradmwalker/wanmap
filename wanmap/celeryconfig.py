from kombu import Exchange, Queue

result_backend = 'rpc://'

task_queues = (
    Queue('console', Exchange('default', type='direct'), routing_key='console'),
)

task_create_missing_queues = False
worker_direct = True
task_default_queue = 'console'
task_default_routing_key = 'console'


class ScanRouter:

    def route_for_task(self, task, args=None, kwargs=None):
        if task == 'wanmap.tasks.exec_nmap_scan':
            scanner_name = args[1]
            return {
                'exchange': 'C.dq2',
                'routing_key': 'scanner@{}'.format(scanner_name)
            }
        return None


task_routes = (ScanRouter(),)
