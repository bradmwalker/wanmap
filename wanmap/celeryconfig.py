from kombu import Exchange, Queue

result_backend = 'redis://'

task_queues = (
    Queue('console', Exchange('default', type='direct'), routing_key='console'),
)

task_create_missing_queues = False
worker_direct = True
task_default_queue = 'console'
task_default_routing_key = 'console'
task_ignore_results = True


class ScanRouter:

    def route_for_task(self, task, args=None, kwargs=None):
        if task == 'wanmap.tasks.exec_nmap_scan':
            scan_id, scanner_name = args[0]
            return {
                'exchange': 'C.dq2',
                'routing_key': 'scanner@{}'.format(scanner_name)
            }
        return None


task_routes = (ScanRouter(),)
