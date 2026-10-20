import time
import sys
sys.path.insert(0, 'backend')

from app.services.neo4j_client import neo4j_client
from app.services.rabbitmq import rabbitmq_pipeline
from app.services.cowrie import cowrie_service

t0 = time.time()
neo4j_client.check_health()
print("neo4j time:", round(time.time() - t0, 3))

t0 = time.time()
rabbitmq_pipeline.check_health()
print("rabbitmq time:", round(time.time() - t0, 3))

t0 = time.time()
cowrie_service.check_health()
print("cowrie time:", round(time.time() - t0, 3))
