#!/bin/bash
broker_ip_address=198.51.100.1
celery_path=/opt/wanmap/bin/celery

# Establish connectivity before starting Celery to ensure celeryd_after_setup
# event messages persist_scanner task.
until nping --tcp -p 6379 -c 1 $broker_ip_address | grep ' SA '; do
    sleep .5
done
sudo -u wanmap $celery_path worker -A wanmap.tasks -b redis://$broker_ip_address -l INFO -n scanner@$(hostname -s) -X console
